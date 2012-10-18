/* smack.c - Provide interface to query smack context
 *
 * Author: Brian McGillion <brian.mcgillion@intel.com>
 * Copyright © 2012 Intel Corporation
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <config.h>
#include "smack.h"

#include <dbus/dbus-internals.h>

#include "connection.h"
#include "services.h"
#include "utils.h"

#include <stdlib.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef DBUS_ENABLE_SMACK
#include <sys/smack.h>
#endif

char *
bus_smack_get_label (DBusConnection *connection, DBusError *error)
{
#ifdef DBUS_ENABLE_SMACK
  char *label;
  int sock_fd;

  if (!dbus_connection_get_socket(connection, &sock_fd))
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to get the socket descriptor of the connection.\n");
      _dbus_verbose ("Failed to get socket descriptor of connection for Smack check.%s\n");
      return NULL;
    }

  /* retrieve an ascii, null-terminated string that defines the Smack context of the connected socket */
  if (smack_new_label_from_socket(sock_fd, &label) < 0)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to read the Smack context from the connection: %s.\n",
                      _dbus_strerror (errno));
      _dbus_verbose ("Failed to read the Smack context from the connection: %s.\n",
                     _dbus_strerror (errno));
      return NULL;
    }
  return label;
#else
  return NULL;
#endif
}

void
bus_smack_label_free (char *label)
{
  if (label)
    free (label);
}
