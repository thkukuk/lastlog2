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
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include <lastlog.h>

#include "lastlog2.h"

static sqlite3 *
open_database_ro (const char *path, char **error)
{
  sqlite3 *db;

  if (sqlite3_open_v2 (path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "Cannot open database (%s): %s",
		      path, sqlite3_errmsg (db)) < 0)
	  *error = strdup ("Out of memory");
      sqlite3_close (db);
      return NULL;
    }

  return db;
}

static sqlite3 *
open_database_rw (const char *path, char **error)
{
  sqlite3 *db;

  if (sqlite3_open (path, &db) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "Cannot create/open database (%s): %s",
		      path, sqlite3_errmsg (db)) < 0)
	  *error = strdup ("Out of memory");

      sqlite3_close (db);
      return NULL;
    }

  return db;
}

/* Reads one entry from database and returns that.
   Returns 0 on success, -1 on failure. */
static int
read_entry (sqlite3 *db, const char *user,
	    int64_t *ll_time, char **tty, char **rhost, char **error)
{
  int retval = 0;
  sqlite3_stmt *res;
  char *sql = "SELECT * FROM Lastlog WHERE Name = ?";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "Failed to execute statement: %s",
		      sqlite3_errmsg (db)) < 0)
	  *error = strdup ("Out of memory");

      return -1;
    }

  if (sqlite3_bind_text (res, 1, user, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "Failed to create search query: %s",
		      sqlite3_errmsg (db)) < 0)
	  *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int step = sqlite3_step (res);

  if (step == SQLITE_ROW)
    {
      const unsigned char *luser = sqlite3_column_text (res, 0);
      const unsigned char *uc;

      if (strcmp ((const char *)luser, user) != 0)
	{
	  if (error)
	    if (asprintf (error, "Returned data is for %s, not %s", luser, user) < 0)
	      *error = strdup("Out of memory");

	  sqlite3_finalize (res);
	  return -1;
	}

      if (ll_time)
	*ll_time = sqlite3_column_int64 (res, 1);

      if (tty)
	{
	  uc = sqlite3_column_text (res, 2);
	  if (uc != NULL && strlen ((const char *)uc) > 0)
	    *tty = strdup ((const char *)uc);
	}
      if (rhost)
	{
	  uc = sqlite3_column_text (res, 3);
	  if (uc != NULL && strlen ((const char *)uc) > 0)
	    *rhost = strdup ((const char *)uc);
	}
    }
  else
    {
      if (error)
	if (asprintf (error, "User '%s' not found (%d)", user, step) < 0)
	  *error = strdup("Out of memory");

      retval = -1;
    }

  sqlite3_finalize (res);

  return retval;
}

/* reads 1 entry from database and returns that. Returns 0 on success, -1 on failure. */
int
ll2_read_entry (const char *lastlog2_path, const char *user,
		int64_t *ll_time, char **tty, char **rhost, char **error)
{
  sqlite3 *db;
  int retval;

  if ((db = open_database_ro (lastlog2_path, error)) == NULL)
    return -1;

  retval = read_entry (db, user, ll_time, tty, rhost, error);

  sqlite3_close (db);

  return retval;
}

/* Write a new entry. Returns 0 on success, -1 on failure. */
static int
write_entry (sqlite3 *db, const char *user,
	     int64_t ll_time, const char *tty, const char *rhost,
		 char **error)
{
  char *err_msg = NULL;
  char *sql;

  if (asprintf (&sql, "CREATE TABLE IF NOT EXISTS Lastlog(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT) STRICT;"
		"REPLACE INTO Lastlog VALUES('%s', %llu, '%s', '%s');",
		user, (long long int)ll_time, tty ? tty : "",
		rhost ? rhost : "") < 0)
    {
      *error = strdup("Out of memory");
      return -1;
    }

  if (sqlite3_exec (db, sql, 0, 0, &err_msg) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "SQL error: %s", err_msg) < 0)
	  *error = strdup ("Out of memory");
      sqlite3_free (err_msg);
      free (sql);
      return -1;
    }

  free (sql);

  return 0;
}

/* Write a new entry. Returns 0 on success, -1 on failure. */
int
ll2_write_entry (const char *lastlog2_path, const char *user,
		 int64_t ll_time, const char *tty, const char *rhost,
		 char **error)
{
  sqlite3 *db;
  int retval;

  if ((db = open_database_rw (lastlog2_path, error)) == NULL)
    return -1;

  retval = write_entry (db, user, ll_time, tty, rhost, error);

  sqlite3_close (db);

  return retval;
}

/* Write a new entry. Returns 0 on success, -1 on failure. */
int
ll2_update_login_time (const char *lastlog2_path, const char *user,
		       int64_t ll_time, char **error)
{
  sqlite3 *db;
  int retval;
  char *tty;
  char *rhost;

  if ((db = open_database_rw (lastlog2_path, error)) == NULL)
    return -1;

  if (read_entry (db, user, 0, &tty, &rhost, error) != 0)
    {
      sqlite3_close (db);
      return -1;
    }

  retval = write_entry (db, user, ll_time, tty, rhost, error);

  sqlite3_close (db);

  if (tty)
    free (tty);
  if (rhost)
    free (rhost);

  return retval;
}


typedef int (*callback_f)(const char *user, int64_t ll_time,
			  const char *tty, const char *rhost);

static int
callback (void *cb_func, int argc, char **argv, char **azColName)
{
  char *endptr;
  callback_f print_entry = cb_func;

  if (argc != 4)
    {
      fprintf (stderr, "Mangled entry:");
      for (int i = 0; i < argc; i++)
	fprintf (stderr, " %s=%s", azColName[i], argv[i] ? argv[i] : "NULL");
      fprintf (stderr, "\n");
      exit (EXIT_FAILURE);
    }

  errno = 0;
  int64_t ll_time = strtol(argv[1], &endptr, 10);
  if ((errno == ERANGE && (ll_time == LONG_MAX || ll_time == LONG_MIN))
      || (endptr == argv[1]) || (*endptr != '\0'))
    fprintf (stderr, "Invalid numeric time entry for '%s': '%s'\n", argv[0], argv[1]);

  print_entry (argv[0], ll_time, argv[2], argv[3]);

  return 0;
}

/* Reads all entries from database and calls the callback function for each entry.
   Returns 0 on success, -1 on failure. */
int
ll2_read_all  (const char *lastlog2_path,
	       int (*cb_func)(const char *user, int64_t ll_time,
			      const char *tty, const char *rhost),
	       char **error)
{
  sqlite3 *db;
  char *err_msg = 0;

  if ((db = open_database_ro (lastlog2_path, error)) == NULL)
    return -1;

  char *sql = "SELECT * FROM Lastlog";

  if (sqlite3_exec (db, sql, callback, cb_func, &err_msg) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "SQL error: %s", err_msg) < 0)
	  *error = strdup ("Out of memory");

      sqlite3_free (err_msg);
      sqlite3_close (db);
      return -1;
    }

  sqlite3_close (db);

  return 0;
}

/* Remove an user entry. Returns 0 on success, -1 on failure. */
static int
remove_entry (sqlite3 *db, const char *user, char **error)
{
  sqlite3_stmt *res;
  char *sql = "DELETE FROM Lastlog WHERE Name = ?";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("Out of memory");

      return -1;
    }

  if (sqlite3_bind_text (res, 1, user, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create delete statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int step = sqlite3_step (res);

  if (step != SQLITE_DONE)
    {
      if (error)
        if (asprintf (error, "Delete statement did not return SQLITE_DONE: %d",
                      step) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  sqlite3_finalize(res);

  return 0;
}

/* Remove an user entry. Returns 0 on success, -1 on failure. */
int
ll2_remove_entry (const char *lastlog2_path, const char *user,
		 char **error)
{
  sqlite3 *db;
  int retval;

  if ((db = open_database_rw (lastlog2_path, error)) == NULL)
    return -1;

  retval = remove_entry (db, user, error);

  sqlite3_close (db);

  return retval;
}

/* Renames an user entry. Returns 0 on success, -1 on failure. */
int
ll2_rename_user (const char *lastlog2_path, const char *user,
		 const char *newname, char **error)
{
  sqlite3 *db;
  time_t ll_time;
  char *tty;
  char *rhost;
  int retval;

  if ((db = open_database_rw (lastlog2_path, error)) == NULL)
    return -1;

  if (read_entry (db, user, &ll_time, &tty, &rhost, error) != 0)
    {
      sqlite3_close (db);
      return -1;
    }

  if (write_entry (db, newname, ll_time, tty, rhost, error) != 0)
    {
      sqlite3_close (db);
      if (tty)
	free (tty);
      if (rhost)
	free (rhost);
      return -1;
    }

  retval = remove_entry (db, user, error);

  sqlite3_close (db);

  if (tty)
    free (tty);
  if (rhost)
    free (rhost);

  return retval;
}

/* Import old lastlog file.
   Returns 0 on success, -1 on failure. */
int
ll2_import_lastlog (const char *lastlog2_path, const char *lastlog_file,
		    char **error)
{
  const struct passwd *pw;
  struct stat statll;
  sqlite3 *db;
  FILE *ll_fp;

  if ((db = open_database_rw (lastlog2_path, error)) == NULL)
    return -1;

  ll_fp = fopen (lastlog_file, "r");
  if (ll_fp == NULL)
    {
      if (error)
	if (asprintf (error, "Failed to open '%s': %s",
		      lastlog_file, strerror (errno)) < 0)
	  *error = strdup ("Out of memory");

      return -1;
    }


  if (fstat (fileno (ll_fp), &statll) != 0)
    {
      if (error)
	if (asprintf (error, "Cannot get size of '%s': %s",
		      lastlog_file, strerror (errno)) < 0)
	  *error = strdup ("Out of memory");
      return -1;
    }

  setpwent ();
  while ((pw = getpwent ()) != NULL )
    {
      off_t offset;
      struct lastlog ll;

      offset = (off_t) pw->pw_uid * sizeof (ll);

      if ((offset + (off_t)sizeof (ll)) <= statll.st_size)
	{
	  if (fseeko (ll_fp, offset, SEEK_SET) == -1)
	    continue; /* Ignore seek error */

	  if (fread (&ll, sizeof (ll), 1, ll_fp) != 1)
	    {
	      if (error)
		if (asprintf (error, "Failed to get the entry for UID '%lu'",
			      (unsigned long int)pw->pw_uid) < 0)
		  *error = strdup ("Out of memory");

	      endpwent ();
	      sqlite3_close (db);
	      return -1;
	    }

	  if (ll.ll_time != 0)
	    {
	      time_t ll_time;
	      char tty[UT_LINESIZE+1];
	      char rhost[UT_HOSTSIZE+1];

	      ll_time = ll.ll_time;
	      strncpy (tty, ll.ll_line, UT_LINESIZE);
	      tty[UT_LINESIZE] = '\0';
	      strncpy (rhost, ll.ll_host, UT_HOSTSIZE);
	      rhost[UT_HOSTSIZE] = '\0';

	      if (write_entry (db, pw->pw_name, ll_time, tty,
			       rhost, error) != 0)
		{
		  endpwent ();
		  sqlite3_close (db);
		  return -1;
		}
	    }
	}
    }

  endpwent ();
  sqlite3_close (db);

  return 0;
}
