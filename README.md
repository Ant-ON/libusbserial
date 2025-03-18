# libusbserial
USB serial driver library.

## Using
```c
#include <libusb.h>
#include <libusbserial.h>

/**
 * Read data callback.
 * @param data recieved data
 * @param length length of recieved data
 * @param user_data user data which set in usbserial_port_init
 */
void read_cb(void *data, size_t length, void *user_data)
{
  printf("%s", (char*)data);
}

/**
 * Example of using serial library on Android device.
 * @param fd filedescriptor of USB device
 * @see http://developer.android.com/reference/android/hardware/usb/UsbDeviceConnection.html#getFileDescriptor
 */
void example(int fd)
{
  libusb_set_option(NULL, LIBUSB_OPTION_WEAK_AUTHORITY, NULL);

  libusb_context *ctx;
  libusb_init(&ctx);

  /* wrap FD */
  libusb_device_handle *usb_handle;
  libusb_wrap_sys_device(NULL, (intptr_t)fd, &usb_handle);

  /* open serial port */
  void *user_data = NULL;
  struct usbserial_port *port;
  int r = usbserial_port_init(&port, usb_handle, 0, read_cb, NULL, user_data);
  if (!r)
  {
    struct usbserial_config config;
    memset(&config, 0, sizeof(config));
    config.baud = 115200;
    config.data_bits = USBSERIAL_DATABITS_8;
    config.parity = USBSERIAL_PARITY_NONE;
    config.stop_bits = USBSERIAL_STOPBITS_1;
    usbserial_port_set_config(port, &config);
    usbserial_start_reader(port);

    usbserial_write(port, "SEND DATA", 10);

    usleep(2000); // Waiting respond...

    usbserial_stop_reader(port);
    usbserial_port_deinit(port);
  }

  libusb_close(usb_handle);
  libusb_exit(ctx);
}
```
