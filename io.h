/*
 * libusbserial
 * 
 * Copyright (C) 2019 Anton Prozorov <prozanton@gmail.com>
 * Copyright (c) 2014-2015 Felix Hädicke
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef LIBUSBSERIAL_IO_H
#define LIBUSBSERIAL_IO_H

#include "internal.h"

int usbserial_io_init_bulk_read_transfer(struct usbserial_port *port);

int usbserial_io_cancel_bulk_read_transfer(struct usbserial_port *port);

int usbserial_io_bulk_read(struct usbserial_port *port,
        void *data, size_t size, int timeout);

int usbserial_io_bulk_write(struct usbserial_port *port,
        const void *data, size_t size);

int usbserial_io_get_endpoint(struct usbserial_port *port, uint8_t classs);

int usbserial_io_free_endpoint(struct usbserial_port *port);

#endif // LIBUSBSERIAL_IO_H
