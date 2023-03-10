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

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <sqlite3.h>

#include "lastlog2.h"

static char *lastlog2_path = _PATH_LASTLOG2;

static int
print_entry (const char *user, time_t ll_time,
	     const char *tty, const char *rhost)
{
  static int once = 0;
  char *datep;
  struct tm *tm;
  char datetime[80];
  /* IPv6 address is at maximum 39 characters.
     But for LL-addresses (fe80+only) the interface should be set,
     so LL-address + % + IFNAMSIZ. */
  const int maxIPv6Addrlen = 42;

  if (!once)
    {
      printf ("Username         Port     From%*sLatest\n", maxIPv6Addrlen-3, " ");
      once = 1;
    }

  tm = localtime (&ll_time);
  if (tm == NULL)
    datep = "(unknown)";
  else
    {
      strftime (datetime, sizeof (datetime), "%a %b %e %H:%M:%S %z %Y", tm);
      datep = datetime;
    }

  if (ll_time == (time_t) 0)
    datep = "**Never logged in**";

  printf ("%-16s %-8.8s %*s%s\n", user, tty ? tty : "",
	  -maxIPv6Addrlen, rhost ? rhost : "", datep);

  return 0;
}

/* reads 1 entry from database and prints that.
   returns 0 on success, 1 on failure. */
static int
read_sqlite_user (const char *user, time_t *ll_time,
		  char **tty, char **rhost)
{
  sqlite3 *db;
  sqlite3_stmt *res;
  int r;

  if ((r = sqlite3_open_v2 (lastlog2_path, &db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
      fprintf (stderr, "Cannot open database (%s): %s\n",
	       lastlog2_path, sqlite3_errmsg (db));
      sqlite3_close (db);
      return 1;
    }

  char *sql = "SELECT * FROM Lastlog WHERE Name = ?";

  if ((r = sqlite3_prepare_v2 (db, sql, -1, &res, 0)) != SQLITE_OK)
    {
      fprintf (stderr, "Failed to execute statement: %s\n",
	       sqlite3_errmsg (db));
      sqlite3_close (db);
      return 1;
    }

  if ((r = sqlite3_bind_text (res, 1, user, -1, SQLITE_STATIC)) != SQLITE_OK)
    {
      fprintf (stderr, "Failed to create search query (%i): %s\n", r,
		  sqlite3_errmsg (db));
      sqlite3_finalize(res);
      sqlite3_close (db);
      return 1;
    }

  int step = sqlite3_step (res);

  if (step == SQLITE_ROW)
    {
      const unsigned char *luser = sqlite3_column_text (res, 0);
      const unsigned char *uc;

      if (strcmp ((const char *)luser, user) != 0)
	{
	  fprintf (stderr, "Returned data is for %s, not %s\n", luser, user);
	  sqlite3_close (db);
	  return 1;
	}

      *ll_time = sqlite3_column_int64 (res, 1);
      uc = sqlite3_column_text (res, 2);
      if (uc != NULL && strlen ((const char *)uc) > 0)
	*tty = strdup ((const char *)uc);

      uc = sqlite3_column_text (res, 3);
      if (uc != NULL && strlen ((const char *)uc) > 0)
	*rhost = strdup ((const char *)uc);
    }

  sqlite3_finalize(res);
  sqlite3_close (db);

  return 0;
}

static int
callback (void *NotUsed __attribute__((unused)),
	  int argc, char **argv, char **azColName)
{
  char *endptr;

  if (argc != 4)
    {
      fprintf (stderr, "Mangled entry:");
      for (int i = 0; i < argc; i++)
	fprintf (stderr, " %s=%s", azColName[i], argv[i] ? argv[i] : "NULL");
      fprintf (stderr, "\n");
      exit (EXIT_FAILURE);
    }


  errno = 0;
  time_t ll_time = strtol(argv[1], &endptr, 10);
  if ((errno == ERANGE && (ll_time == LONG_MAX || ll_time == LONG_MIN))
      || (endptr == argv[1]) || (*endptr != '\0'))
    fprintf (stderr, "Invalid numeric time entry for '%s': '%s'\n", argv[0], argv[1]);

  print_entry (argv[0], ll_time, argv[2], argv[3]);

  return 0;
}

/* reads all entry from database and calls the callback function for each entry.
   returns 0 on success, 1 on failure. */
static int
read_sqlite_all (void)
{
  sqlite3 *db;
  char *err_msg = 0;
  int r;

  if ((r = sqlite3_open_v2 (lastlog2_path, &db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
      fprintf (stderr, "Cannot open database (%s): %s\n",
	       lastlog2_path, sqlite3_errmsg (db));
      sqlite3_close (db);
      return 1;
    }

  char *sql = "SELECT * FROM Lastlog";

  if (sqlite3_exec (db, sql, callback, 0, &err_msg) != SQLITE_OK)
    {
      fprintf (stderr, "SQL error: %s\n", err_msg);
      sqlite3_free (err_msg);
      sqlite3_close (db);
      return 1;
    }

  sqlite3_close (db);

  return 0;
}

/* Write a new entry.
   returns 0 on success, 1 on failure. */
static int
write_sqlite(const char *user, time_t ll_time,
	     const char *tty, const char *rhost)
{
  sqlite3 *db;
  char *err_msg = 0;

  if (sqlite3_open (lastlog2_path, &db) != SQLITE_OK)
    {
      fprintf (stderr, "Cannot open database (%s): %s\n",
	       lastlog2_path, sqlite3_errmsg (db));
      sqlite3_close (db);
      return 1;
    }

  char *sql;
  if (asprintf (&sql, "CREATE TABLE IF NOT EXISTS Lastlog(Name TEXT PRIMARY KEY, Time INT, TTY TEXT, RemoteHost TEXT);"
		"REPLACE INTO Lastlog VALUES('%s', %lu, '%s', '%s');",
		user, ll_time, tty ? tty : "", rhost ? rhost : "") < 0)
    return 1;

  if (sqlite3_exec (db, sql, 0, 0, &err_msg) != SQLITE_OK)
    {
      fprintf (stderr, "SQL error: %s\n", err_msg);
      sqlite3_free (err_msg);
      sqlite3_close (db);
      free (sql);
      return 1;
    }

  free (sql);
  sqlite3_close (db);

  return 0;
}

static void
usage (int retval)
{
  FILE *output = (retval != EXIT_SUCCESS) ? stderr : stdout;

  fprintf (output, "Usage: lastlog2 [options]\n\n"
	   "Options:\n");
  fputs ("  -b, --before DAYS    Print only records older than DAYS\n", output);
  fputs ("  -C, --clear          Clear record of a user (requires -u)\n", output);
  fputs ("  -d, --database FILE  Use FILE as lastlog2 database\n", output);
  fputs ("  -h, --help           Display this help message and exit\n", output);
  fputs ("  -S, --set            Set lastlog record to current time (requires -u)\n", output);
  fputs ("  -t, --time DAYS      print only lastlog records more recent than DAYS\n", output);
  fputs ("  -u, --user LOGIN     print lastlog record of the specified LOGIN\n", output);
  fputs ("\n", output);
  exit (retval);
}

int
main (int argc, char **argv)
{
  struct option const longopts[] = {
    {"before",   required_argument, NULL, 'b'},
    {"clear",    no_argument,       NULL, 'C'},
    {"database", required_argument, NULL, 'd'},
    {"help",     no_argument,       NULL, 'h'},
    {"set",      no_argument,       NULL, 'S'},
    {"time",     required_argument, NULL, 't'},
    {"user",     required_argument, NULL, 'u'},
    {NULL, 0, NULL, '\0'}
  };
  int bflg = 0;
  time_t b_days = 0;
  int Cflg = 0;
  int Sflg = 0;
  int tflg = 0;
  time_t t_days = 0;
  int uflg = 0;
  const char *user = NULL;
  int c;

  while ((c = getopt_long (argc, argv, "b:Cd:hSt:u:", longopts, NULL)) != -1)
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

  if (Cflg && Sflg)
    {
      fprintf (stderr, "Option -C cannot be used together with option -S\n");
      usage (EXIT_FAILURE);
    }

  if (Cflg || Sflg)
    {
      if (!uflg || strlen (user) == 0)
	{
	  fprintf (stderr, "Options -C and -S require option -u to specify the user\n");
	  usage (EXIT_FAILURE);
	}

      if (Cflg)
	{
	  /* XXX */
	}

      if (Sflg)
	{
	  time_t ll_time = 0;
	  char *tty = NULL;
	  char *rhost = NULL;

	  if (read_sqlite_user (user, &ll_time, &tty, &rhost) != 0)
	    exit (EXIT_FAILURE);

	  if (time (&ll_time) == -1)
	    {
	      fprintf (stderr, "Could not determine current time: %s",
		       strerror (errno));
	      exit (EXIT_FAILURE);
	    }

	  if (write_sqlite (user, ll_time, tty, rhost) != 0)
	    exit (EXIT_FAILURE);

	  if (tty)
	    free (tty);
	  if (rhost)
	    free (rhost);

	  exit (EXIT_SUCCESS);
	}
    }

  if (user)
    {
      time_t ll_time = 0;
      char *tty = NULL;
      char *rhost = NULL;

      if (read_sqlite_user (user, &ll_time, &tty, &rhost) != 0)
	exit (EXIT_FAILURE);

      print_entry(user, ll_time, tty, rhost);

      exit (EXIT_SUCCESS);
    }

  return read_sqlite_all ();
}
