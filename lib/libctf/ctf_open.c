/*	$OpenBSD$	*/

/*
 * Copyright (c) 2016 Martin Pieuchot <mpi@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include <sys/exec_elf.h>

#include "ctf.h"
#include "ctf_impl.h"

static char	*ctf_decompress(const char *, size_t, size_t);

ctf_file_t *
ctf_open(const char *path)
{
	ctf_file_t	*cf = NULL;
	Elf		*e = NULL;
	Elf_Scn		*scn, *scnctf = NULL;
	Elf_Data	*data;
	GElf_Shdr	 shdr;
	struct stat	 st;
	size_t		 shstrndx;
	char		*name;
	const char	*rawctf;
	size_t		 rawctflen;
	int		 fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return NULL;

	if (elf_version(EV_CURRENT) == EV_NONE)
		goto fail;

	e = elf_begin(fd, ELF_C_READ, NULL);
	if (e == NULL)
		goto fail;

	cf = calloc(1, sizeof(*cf));
	if (cf == NULL)
		goto fail;

	cf->fd = fd;

	if (elf_kind(e) == ELF_K_ELF) {
		/* ELF path */
		if (elf_getshdrstrndx(e, &shstrndx) != 0)
			goto fail;

		cf->elf = e;

		scn = NULL;
		while ((scn = elf_nextscn(e, scn)) != NULL) {
			if (gelf_getshdr(scn, &shdr) != &shdr)
				goto fail;

			name = elf_strptr(e, shstrndx, shdr.sh_name);
			if (name == NULL)
				continue;

			if (strcmp(name, ELF_CTF) == 0)
				scnctf = scn;

			if (strcmp(name, ELF_SYMTAB) == 0 &&
			    shdr.sh_type == SHT_SYMTAB &&
			    shdr.sh_entsize != 0) {
				cf->symtab = scn;
				cf->nsymb = shdr.sh_size / shdr.sh_entsize;
			}

			if (strcmp(name, ELF_STRTAB) == 0 &&
			    shdr.sh_type == SHT_STRTAB) {
				cf->strtabndx = elf_ndxscn(scn);
				cf->strtabsz = shdr.sh_size;
			}
		}

		if (scnctf == NULL)
			goto fail;

		data = elf_rawdata(scnctf, NULL);
		if (data == NULL || data->d_buf == NULL)
			goto fail;

		rawctf = data->d_buf;
		rawctflen = data->d_size;
	} else {
		/* Raw CTF path */
		elf_end(e);
		e = NULL;
		cf->elf = NULL;

		if (fstat(fd, &st) == -1)
			goto fail;

		if ((uintmax_t)st.st_size > SIZE_MAX)
			goto fail;

		cf->rawmap = mmap(NULL, st.st_size, PROT_READ,
		    MAP_PRIVATE, fd, 0);
		if (cf->rawmap == MAP_FAILED) {
			cf->rawmap = NULL;
			goto fail;
		}
		cf->rawmaplen = st.st_size;

		rawctf = cf->rawmap;
		rawctflen = st.st_size;
	}

	/* Common: validate CTF header and load data */
	if (rawctflen < sizeof(struct ctf_header))
		goto fail;

	memcpy(&cf->cth, rawctf, sizeof(cf->cth));

	if (cf->cth.cth_magic != CTF_MAGIC ||
	    cf->cth.cth_version != CTF_VERSION)
		goto fail;

	cf->dlen = cf->cth.cth_stroff + cf->cth.cth_strlen;

	if (cf->cth.cth_flags & CTF_F_COMPRESS) {
		cf->data = ctf_decompress(rawctf + sizeof(cf->cth),
		    rawctflen - sizeof(cf->cth), cf->dlen);
		if (cf->data == NULL)
			goto fail;
		cf->needfree = 1;
	} else {
		cf->data = (char *)rawctf + sizeof(cf->cth);
		cf->needfree = 0;
	}

	return cf;

fail:
	if (cf != NULL) {
		if (cf->needfree)
			free(cf->data);
		if (cf->rawmap != NULL)
			munmap(cf->rawmap, cf->rawmaplen);
		free(cf);
	}
	if (e != NULL)
		elf_end(e);
	close(fd);
	return NULL;
}

void
ctf_close(ctf_file_t *cf)
{
	if (cf == NULL)
		return;

	if (cf->needfree)
		free(cf->data);
	if (cf->rawmap != NULL)
		munmap(cf->rawmap, cf->rawmaplen);
	if (cf->elf != NULL)
		elf_end(cf->elf);
	if (cf->fd >= 0)
		close(cf->fd);
	free(cf);
}

static char *
ctf_decompress(const char *buf, size_t size, size_t len)
{
	z_stream	 stream;
	char		*data;
	int		 error;

	data = malloc(len);
	if (data == NULL)
		return NULL;

	memset(&stream, 0, sizeof(stream));
	stream.next_in = (void *)buf;
	stream.avail_in = size;
	stream.next_out = (uint8_t *)data;
	stream.avail_out = len;

	if ((error = inflateInit(&stream)) != Z_OK)
		goto fail;

	if ((error = inflate(&stream, Z_FINISH)) != Z_STREAM_END) {
		inflateEnd(&stream);
		goto fail;
	}

	if ((error = inflateEnd(&stream)) != Z_OK)
		goto fail;

	if (stream.total_out != len)
		goto fail;

	return data;

fail:
	free(data);
	return NULL;
}
