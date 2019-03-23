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

#ifndef LIBUSBSERIAL_DRIVER_H
#define LIBUSBSERIAL_DRIVER_H

#include "libusbserial.h"

struct usbserial_driver
{
    int (*check_supported_by_vid_pid)(uint16_t vid, uint16_t pid);
    int (*check_supported_by_class)(
            uint8_t class,
            uint8_t subclass);
    const char* (*get_device_name)(
            uint16_t vid,
            uint16_t pid,
            uint8_t classs,
            uint8_t subclass);
    unsigned int (*get_ports_count)(uint16_t vid, uint16_t pid);

    int (*port_init)(struct usbserial_port *port);
    int (*port_deinit)(struct usbserial_port *port);

    int (*port_set_config)(
            struct usbserial_port *port,
            const struct usbserial_config* config);

    int (*start_reader)(struct usbserial_port *port);
    int (*stop_reader)(struct usbserial_port *port);

    int (*read)(
            struct usbserial_port *port,
            void *data,
            size_t size,
			int timeout);
    int (*write)(
            struct usbserial_port *port,
            const void *data,
            size_t size);
    int (*purge)(
            struct usbserial_port *port,
            int rx,
            int tx);

    void (*read_data_process)(
            struct usbserial_port *port,
            void *data,
            size_t *size);
			
	int (*set_dtr_rts)(
            struct usbserial_port *port,
            int dtr,
            int rts);
};

#endif // LIBUSBSERIAL_DRIVER_H
