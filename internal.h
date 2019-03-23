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

#ifndef LIBUSBSERIAL_INTERNAL_H
#define LIBUSBSERIAL_INTERNAL_H

#include "libusbserial.h"

#include "config.h"

#include <stdint.h>

#define UNUSED_VAR(x) ((void)x)

#ifndef max
#define max(a,b) (((a) (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#include <pthread.h>

struct usbserial_endpoints
{
	uint8_t in;
	uint8_t out;
	uint8_t in_if;
	uint8_t out_if;
};

struct usbserial_port
{
    const struct usbserial_driver *driver;

	unsigned int port_idx;
	struct usbserial_endpoints endp;
	
	libusb_device *usb_dev;
    libusb_device_handle *usb_dev_hdl;
    struct libusb_device_descriptor usb_dev_desc;

	struct libusb_transfer *read_transfer;
    usbserial_cb_read_fn cb_read;
    usbserial_cb_error_fn cb_read_error;
    void *cb_user_data;

	pthread_mutex_t mutex;
	volatile int read_cancel_flag;
    unsigned char read_buffer[READ_BUFFER_SIZE];

	void *driver_data;
};

#endif // LIBUSBSERIAL_INTERNAL_H
