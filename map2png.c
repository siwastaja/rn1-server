#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <png.h>
#include <errno.h>


#define UNIT_FREE	0
#define UNIT_ITEM	(1<<0)	// Small obstacle, detected by sonars or bumping into it
#define UNIT_WALL	(1<<1)	// Obstacle seen by the lidar.
#define UNIT_DO_NOT_REMOVE_BY_LIDAR (1<<2)
#define UNIT_DBG	(1<<6)
#define UNIT_MAPPED		 (1<<7)	// We have seen this area.

#define CONSTRAINT_FORBIDDEN 	(1<<0)	// "Don't go here" unit

typedef struct __attribute__ ((packed))
{
	uint8_t result;	 	// Mapping result decided based on all available data.
	uint8_t latest;		// Mapping result based on last scan.

	uint16_t timestamp;	// Latest time scanned

	uint8_t num_seen;		// Number of times mapped. Saturated at 255.
	uint8_t num_obstacles;	// "is an obstacle" counter. Every time mapped, ++ if obstacle, -- if not. Saturated at 255.

	uint8_t constraints;
	uint8_t reserved;
} map_unit_t;

#define MAP_PAGE_W 256

typedef struct
{
	map_unit_t units[MAP_PAGE_W][MAP_PAGE_W];
} map_page_t;

map_page_t page;

#define WALL_LEVEL(i) ((int)(i).num_obstacles*4)

int main(int argc, char** argv)
{

	if(argc != 3)
	{
		fprintf(stderr, "Usage: map2png in.map out.png\n");
		return 1;
	}

	FILE *f = fopen(argv[1], "r");
	if(!f)
	{
		if(errno == ENOENT)
			return 2;
		fprintf(stderr, "Error %d opening %s for read\n", errno, argv[1]);
		return 3;
	}

	int ret;
	if( (ret = fread(&page, sizeof(map_page_t), 1, f)) != 1)
	{
		fprintf(stderr, "Error: Reading map data failed, fread returned %d. feof=%d, ferror=%d\n", ret, feof(f), ferror(f));
		fclose(f);
		return 4;

	}
	fclose(f);


	int x,y;

	FILE *fp = fopen(argv[2], "wb");
	if(!fp)
	{
		fprintf(stderr, "Opening %s for write failed, errno=%d\n", argv[2], errno);
		return 5;
	}

	png_bytep *row_pointers;


	row_pointers = malloc(sizeof(png_bytep) * MAP_PAGE_W);
	for(y = 0; y < MAP_PAGE_W; y++)
	{
		row_pointers[y] = malloc(MAP_PAGE_W*4);
	}

	for(y = 0; y < MAP_PAGE_W; y++)
	{
		png_bytep row = row_pointers[y];
		for(x = 0; x < MAP_PAGE_W; x++)
		{
			png_bytep px = &(row[x * 4]);

			int alpha = (30*(int)page.units[x][y].num_seen)/3 + (255/3);
			if(alpha > 255) alpha=255;

			int back_r = 170, back_g = 200, back_b = 230;

			int r = 0, g = 0, b = 0;
			if(page.units[x][y].num_obstacles)
			{
				int lvl = WALL_LEVEL(page.units[x][y]);
				if(lvl > 140) lvl = 140;
				int color = 140 - lvl;
				if(!(page.units[x][y].result & UNIT_WALL))
				{
					color = 255;
				}

				r = color;
				g = color;
				b = color;
			}
			else if(page.units[x][y].result & UNIT_ITEM)
			{
				px[0] = 230;
				px[1] = 200;
				px[2] = 230;
			}
			else if(page.units[x][y].result & UNIT_MAPPED)
			{
				r = 255;
				g = 240;
				b = 190;
			}
			else
			{
				r = 210;
				g = 230;
				b = 250;
				alpha = 255;
			}

			int anti_alpha = 255-alpha;
			r = (alpha*r + anti_alpha*back_r)/256;
			g = (alpha*g + anti_alpha*back_g)/256;
			b = (alpha*b + anti_alpha*back_b)/256;

			if(r < 0) r = 0; else if(r > 255) r = 255;
			if(g < 0) r = 0; else if(g > 255) g = 255;
			if(b < 0) r = 0; else if(b > 255) b = 255;
			px[0] = r;
			px[1] = g;
			px[2] = b;
			px[3] = 255;
		}
	}

	png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(!png)
	{
		fprintf(stderr, "libpng fail\n");
		fclose(fp);
		return 6;
	}

	png_infop info = png_create_info_struct(png);
	if(!info)
	{
		fprintf(stderr, "libpng fail\n");
		fclose(fp);
		return 7;
	}

	if(setjmp(png_jmpbuf(png)))
	{
		fprintf(stderr, "libpng fail\n");
		fclose(fp);
		return 8;
	}
	
	png_init_io(png, fp);

	png_set_IHDR(
		png,
		info,
		MAP_PAGE_W, MAP_PAGE_W,
		8, // bits per channel
		PNG_COLOR_TYPE_RGBA,
		PNG_INTERLACE_NONE,
		PNG_COMPRESSION_TYPE_DEFAULT,
		PNG_FILTER_TYPE_DEFAULT
	);
	png_write_info(png, info);

	// To remove alpha channel:
	//png_set_filler(png, 0, PNG_FILLER_AFTER);
	png_write_image(png, row_pointers);
	png_write_end(png, NULL);

	for(y = 0; y < MAP_PAGE_W; y++)
	{
		free(row_pointers[y]);
	}
	free(row_pointers);

	if (png && info)
	        png_destroy_write_struct(&png, &info);

	fclose(fp);

	return 0;
}
