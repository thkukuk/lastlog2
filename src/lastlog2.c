/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2023, Thorsten Kukuk <kukuk@suse.com>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>

#include "lastlog2.h"

static char *lastlog2_path = _PATH_LASTLOG2;

static int bflg = 0;
static time_t b_days = 0;
static int tflg = 0;
static time_t t_days = 0;
static int sflg = 0;

static int
print_entry (const char *user, int64_t ll_time,
	     const char *tty, const char *rhost,
	     const char *pam_service)
{
  static int once = 0;
  char *datep;
  struct tm *tm;
  char datetime[80];
  /* IPv6 address is at maximum 39 characters.
     But for LL-addresses (fe80+only) the interface should be set,
     so LL-address + % + IFNAMSIZ. */
  const int maxIPv6Addrlen = 42;

  /* Print only if older than b days */
  if (bflg && ((time (NULL) - ll_time) < b_days))
    return 0;

  /* Print only if newer than t days */
  if (tflg && ((time (NULL) - ll_time) > t_days))
    return 0;

  /* this is necessary if you compile this on architectures with
     a 32bit time_t type. */
  time_t t_time = ll_time;
  tm = localtime (&t_time);
  if (tm == NULL)
    datep = "(unknown)";
  else
    {
      strftime (datetime, sizeof (datetime), "%a %b %e %H:%M:%S %z %Y", tm);
      datep = datetime;
    }

  if (ll_time == 0)
    datep = "**Never logged in**";

  if (!once)
    {
      printf ("Username         Port     From%*s Latest%*s%s\n",
	      maxIPv6Addrlen-4, " ",
	      sflg?(int)strlen (datep)-5:0, " ", sflg?"Service":"");
      once = 1;
    }
  printf ("%-16s %-8.8s %*s %s%*s%s\n", user, tty ? tty : "",
	  -maxIPv6Addrlen, rhost ? rhost : "", datep,
	  sflg?31-(int)strlen(datep):0, " ", sflg?(pam_service?pam_service:""):"");

  return 0;
}

static void
usage (int retval)
{
  FILE *output = (retval != EXIT_SUCCESS) ? stderr : stdout;

  fprintf (output, "Usage: lastlog2 [options]\n\n"
	   "Options:\n");
  fputs ("  -b, --before DAYS     Print only records older than DAYS\n", output);
  fputs ("  -C, --clear           Clear record of a user (requires -u)\n", output);
  fputs ("  -d, --database FILE   Use FILE as lastlog2 database\n", output);
  fputs ("  -h, --help            Display this help message and exit\n", output);
  fputs ("  -i, --import FILE     Import data from old lastlog file\n", output);
  fputs ("  -r, --rename NEWNAME  Rename existing user to NEWNAME (requires -u)\n", output);
  fputs ("  -s, --service         Display PAM service\n", output);
  fputs ("  -S, --set             Set lastlog record to current time (requires -u)\n", output);
  fputs ("  -t, --time DAYS       Print only lastlog records more recent than DAYS\n", output);
  fputs ("  -u, --user LOGIN      Print lastlog record of the specified LOGIN\n", output);
  fputs ("  -v, --version         Print version number and exit\n", output);
  fputs ("\n", output);
  exit (retval);
}

/* Check if an user exists on the system.
   If yes, return 0, else return -1. */
static int
check_user (const char *name)
{
  if (getpwnam (name) == NULL)
    return -1;
  return 0;
}

int
main (int argc, char **argv)
{
  struct option const longopts[] = {
    {"before",   required_argument, NULL, 'b'},
    {"clear",    no_argument,       NULL, 'C'},
    {"database", required_argument, NULL, 'd'},
    {"help",     no_argument,       NULL, 'h'},
    {"import",   required_argument, NULL, 'i'},
    {"rename",   required_argument, NULL, 'r'},
    {"service",  no_argument,       NULL, 's'},
    {"set",      no_argument,       NULL, 'S'},
    {"time",     required_argument, NULL, 't'},
    {"user",     required_argument, NULL, 'u'},
    {"version",  no_argument,       NULL, 'v'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int Cflg = 0;
  int iflg = 0;
  int rflg = 0;
  int Sflg = 0;
  int uflg = 0;
  const char *user = NULL;
  const char *newname = NULL;
  const char *lastlog_file = NULL;
  int c;

  while ((c = getopt_long (argc, argv, "b:Cd:hi:r:sSt:u:v", longopts, NULL)) != -1)
    {
      switch (c)
	{
	case 'b':
	  {
	    unsigned long days;
	    char *endptr;

	    errno = 0;
	    days = strtoul(optarg, &endptr, 10);
	    if ((errno == ERANGE && days == ULONG_MAX)
		|| (endptr == optarg) || (*endptr != '\0'))
	      {
		fprintf (stderr, "Invalid numeric argument: '%s'\n", optarg);
		exit (EXIT_FAILURE);
	      }
	    b_days = (time_t) days * (24L*3600L) /* seconds/DAY */;
	    bflg = 1;
	  }
	  break;
	case 'C':
	  Cflg = 1;
	  break;
	case 'd':
	  lastlog2_path = optarg;
	  break;
	case 'h':
	  usage (EXIT_SUCCESS);
	  break;
	case 'i':
	  lastlog_file = optarg;
	  iflg = 1;
	  break;
	case 'r':
	  rflg = 1;
	  newname = optarg;
	  break;
	case 's':
	  sflg = 1;
	  break;
	case 'S':
	  /* Set lastlog record of a user to the current time. */
	  Sflg = 1;
	  break;
	case 't':
	  {
	    unsigned long days;
	    char *endptr;

	    errno = 0;
	    days = strtoul(optarg, &endptr, 10);
	    if ((errno == ERANGE && days == ULONG_MAX)
		|| (endptr == optarg) || (*endptr != '\0'))
	      {
		fprintf (stderr, "Invalid numeric argument: '%s'\n", optarg);
		exit (EXIT_FAILURE);
	      }
	    t_days = (time_t) days * (24L*3600L) /* seconds/DAY */;
	    tflg = 1;
	  }
	  break;
	case 'u':
	  uflg = 1;
	  user = optarg;
	  break;
	case 'v':
	  printf ("lastlog2 %s\n", PROJECT_VERSION);
	  exit (EXIT_SUCCESS);
	  break;
	default:
	  usage (EXIT_FAILURE);
	  break;
	}
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  if ((Cflg + Sflg + iflg) > 1)
    {
      fprintf (stderr, "Option -C, -i and -S cannot be used together\n");
      usage (EXIT_FAILURE);
    }

  if (iflg)
    {
      if (ll2_import_lastlog (lastlog2_path, lastlog_file, &error) != 0)
	{
	  if (error)
	    {
	      fprintf (stderr, "%s\n", error);
	      free (error);
	    }
	  else
	    fprintf (stderr, "Couldn't import entries from '%s'\n", lastlog_file);
	  exit (EXIT_FAILURE);
	}
      exit (EXIT_SUCCESS);
    }

  if (Cflg || Sflg || rflg)
    {
      if (!uflg || strlen (user) == 0)
	{
	  fprintf (stderr, "Options -C, -r and -S require option -u to specify the user\n");
	  usage (EXIT_FAILURE);
	}

      if ((Cflg || Sflg) && check_user (user) != 0)
	{
	  fprintf (stderr, "User '%s' does not exist.\n", user);
	  exit (EXIT_FAILURE);
	}

      if (Cflg)
	{
	  if (ll2_remove_entry (lastlog2_path, user, &error) != 0)
	    {
	      if (error)
		{
		  fprintf (stderr, "%s\n", error);
		  free (error);
		}
	      else
		fprintf (stderr, "Couldn't remove entry for '%s'\n", user);
	      exit (EXIT_FAILURE);
	    }
	}

      if (Sflg)
	{
	  time_t ll_time = 0;

	  if (time (&ll_time) == -1)
	    {
	      fprintf (stderr, "Could not determine current time: %s",
		       strerror (errno));
	      exit (EXIT_FAILURE);
	    }

	  if (ll2_update_login_time (lastlog2_path, user, ll_time, &error) != 0)
	    {
	      if (error)
		{
		  fprintf (stderr, "%s\n", error);
		  free (error);
		}
	      else
		fprintf (stderr, "Couldn't update login time for '%s'\n", user);
	      exit (EXIT_FAILURE);
	    }

	}

      if (rflg)
	{
	  if (ll2_rename_user (lastlog2_path, user, newname, &error) != 0)
	    {
	      if (error)
		{
		  fprintf (stderr, "%s\n", error);
		  free (error);
		}
	      else
		fprintf (stderr, "Couldn't rename entry '%s' to '%s'\n", user, newname);
	      exit (EXIT_FAILURE);
	    }
	}

      exit (EXIT_SUCCESS);
    }

  if (user)
    {
      int64_t ll_time = 0;
      char *tty = NULL;
      char *rhost = NULL;
      char *service = NULL;

      if (check_user (user) != 0)
	{
	  fprintf (stderr, "User '%s' does not exist.\n", user);
	  return -1;
	}

      /* We ignore errors, if the user is not in the database he did never login */
      ll2_read_entry (lastlog2_path, user, &ll_time, &tty, &rhost,
		      &service, NULL);

      print_entry(user, ll_time, tty, rhost, service);

      exit (EXIT_SUCCESS);
    }

  if (ll2_read_all (lastlog2_path, print_entry, &error) != 0)
    {
      if (error)
	{
	  fprintf (stderr, "%s\n", error);
	  free (error);
	}
      else
	fprintf (stderr, "Couldn't read entries for all users\n");

      exit (EXIT_FAILURE);
    }

  exit (EXIT_SUCCESS);
}
