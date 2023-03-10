/* SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2023, Thorsten Kukuk <kukuk@suse.com>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sqlite3.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>

#define LASTLOG2_DEBUG        01  /* send info to syslog(3) */
#define LASTLOG2_QUIET        02  /* keep quiet about things */

#define _PATH_LASTLOG2 "/var/log/lastlog2.db"

static int
_pam_parse_args (pam_handle_t *pamh,
		 int flags, int argc,
		 const char **argv)
{
  int ctrl = 0;

  /* does the application require quiet? */
  if (flags & PAM_SILENT)
    ctrl |= LASTLOG2_QUIET;

  /* step through arguments */
  for (; argc-- > 0; ++argv)
    {
      if (!strcmp (*argv,"debug"))
	ctrl |= LASTLOG2_DEBUG;
      else if (!strcmp (*argv,"silent"))
	ctrl |= LASTLOG2_QUIET;
      else
	pam_syslog (pamh, LOG_ERR, "Unknown option: %s", *argv);
    }

  return ctrl;
}

static int
read_sqlite(pam_handle_t *pamh, const char *user, time_t *ll_time,
	    char **tty, char **rhost)
{
  sqlite3 *db;
  sqlite3_stmt *res;
  int r;

  if ((r = sqlite3_open_v2 (_PATH_LASTLOG2, &db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
      /* Don't print error if file does not exist yet */
      if (r != SQLITE_CANTOPEN)
	pam_syslog (pamh, LOG_ERR, "Cannot open database: %s",
		    sqlite3_errmsg (db));
      sqlite3_close (db);
      return PAM_SYSTEM_ERR;
    }

  char *sql = "SELECT * FROM Lastlog WHERE Name = ?";

  if ((r = sqlite3_prepare_v2 (db, sql, -1, &res, 0)) != SQLITE_OK)
    {
      pam_syslog (pamh, LOG_ERR, "Failed to execute statement: %s",
		  sqlite3_errmsg (db));
      sqlite3_close (db);
      return PAM_SYSTEM_ERR;
    }

  if ((r = sqlite3_bind_text (res, 1, user, -1, SQLITE_STATIC)) != SQLITE_OK)
    {
      pam_syslog (pamh, LOG_ERR, "Failed to create search query: %i, %s", r,
		  sqlite3_errmsg (db));
      sqlite3_finalize(res);
      sqlite3_close (db);
      return PAM_SYSTEM_ERR;
    }

  int step = sqlite3_step (res);

  if (step == SQLITE_ROW)
    {
      const unsigned char *luser = sqlite3_column_text(res, 0);
      const unsigned char *uc;

      if (strcmp ((const char *)luser, user) != 0)
	{
	  pam_syslog (pamh, LOG_ERR, "Returned data is for %s, not %s", luser, user);
	  sqlite3_close (db);
	  return PAM_SYSTEM_ERR;
	}

      *ll_time = sqlite3_column_int64 (res, 1);
      uc = sqlite3_column_text (res, 2);
      if (uc != NULL && strlen ((const char *)uc) > 0)
	*tty = strdup ((const char *)uc);

      uc = sqlite3_column_text (res, 3);
      if (uc != NULL && strlen ((const char *)uc) > 0)
	*rhost = strdup ((const char *)uc);

      pam_syslog (pamh, LOG_DEBUG, "user=%s, ll_time=%ld, tty=%s, rhost=%s",
		  luser, *ll_time, *tty, *rhost);
    }

  sqlite3_finalize(res);
  sqlite3_close (db);

  return PAM_SUCCESS;
}


static int
write_sqlite(pam_handle_t *pamh, const char *user, time_t ll_time,
	     const char *tty, const char *rhost)
{
  sqlite3 *db;
  char *err_msg = 0;

  if (sqlite3_open (_PATH_LASTLOG2, &db) != SQLITE_OK)
    {
      pam_syslog (pamh, LOG_ERR, "Cannot open database: %s",
		  sqlite3_errmsg (db));
      sqlite3_close (db);
      return PAM_SYSTEM_ERR;
    }

  char *sql;
  if (asprintf (&sql, "CREATE TABLE IF NOT EXISTS Lastlog(Name TEXT PRIMARY KEY, Time INT, TTY TEXT, RemoteHost TEXT);"
		"REPLACE INTO Lastlog VALUES('%s', %lu, '%s', '%s');",
		user, ll_time, tty, rhost) < 0)
    return PAM_SYSTEM_ERR;

  if (sqlite3_exec (db, sql, 0, 0, &err_msg) != SQLITE_OK)
    {
      pam_syslog (pamh, LOG_ERR, "SQL error: %s", err_msg);
      sqlite3_free (err_msg);
      sqlite3_close (db);
      free (sql);
      return PAM_SYSTEM_ERR;
    }

  free (sql);
  sqlite3_close (db);

  return PAM_SUCCESS;
}


/* From pam_inline.h
 *
 * Returns NULL if STR does not start with PREFIX,
 * or a pointer to the first char in STR after PREFIX.
 */
static inline const char *
skip_prefix(const char *str, const char *prefix)
{
  size_t prefix_len = strlen (prefix);

  return strncmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

static int
write_login_data (pam_handle_t *pamh, int ctrl, const char *user)
{
  const void *void_str;
  const char *tty;
  const char *rhost;
  time_t ll_time;
  int retval;

  void_str = NULL;
  retval = pam_get_item (pamh, PAM_TTY, &void_str);
  if (retval != PAM_SUCCESS || void_str == NULL)
    tty = "";
  else
    tty = void_str;

  /* strip leading "/dev/" from tty. */
  const char *str = skip_prefix(tty, "/dev/");
  if (str != NULL)
    tty = str;

  if (ctrl & LASTLOG2_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "tty=%s", tty);

  void_str = NULL;
  retval = pam_get_item (pamh, PAM_RHOST, &void_str);
  if (retval != PAM_SUCCESS || void_str == NULL)
    rhost = "";
  else
    rhost = void_str;

  if (ctrl & LASTLOG2_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "rhost=%s", rhost);

  if (time (&ll_time) < 0)
    return PAM_SYSTEM_ERR;

  return write_sqlite (pamh, user, ll_time, tty, rhost);
}

static int
show_lastlogin (pam_handle_t *pamh, int ctrl, const char *user)
{
  time_t ll_time = 0;
  char *tty = NULL;
  char *rhost = NULL;
  char *date = NULL;
  char the_time[256];
  int retval;

  if (ctrl & LASTLOG2_QUIET)
    return PAM_IGNORE;

  if ((retval = read_sqlite (pamh, user, &ll_time, &tty, &rhost)) != PAM_SUCCESS)
    return retval;

  if (ll_time)
    {
      struct tm *tm, tm_buf;

      if ((tm = localtime_r (&ll_time, &tm_buf)) != NULL)
	{
	  strftime (the_time, sizeof (the_time),
		    " %a %b %e %H:%M:%S %Z %Y", tm);
	  date = the_time;
	}
    }

  if (date != NULL || rhost != NULL || tty != NULL)
    retval = pam_info(pamh, "Last login:%s%s%s%s%s",
		      date ? date : "",
		      rhost ? " from " : "",
		      rhost ? rhost : "",
		      tty ? " on " : "",
		      tty ? tty : "");

  _pam_drop(rhost);
  _pam_drop(tty);

  return retval;
}

int
pam_sm_authenticate (pam_handle_t *pamh __attribute__((__unused__)),
		     int flags __attribute__((__unused__)),
		     int argc __attribute__((__unused__)),
		     const char **argv __attribute__((__unused__)))
{
  return PAM_IGNORE;
}

int
pam_sm_setcred (pam_handle_t *pamh __attribute__((__unused__)),
		int flags __attribute__((__unused__)),
		int argc __attribute__((__unused__)),
		const char **argv __attribute__((__unused__)))
{
  return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh __attribute__((__unused__)),
		  int flags __attribute__((__unused__)),
		  int argc __attribute__((__unused__)),
		  const char **argv __attribute__((__unused__)))
{
  return PAM_IGNORE;
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  const struct passwd *pwd;
  const void *void_str;
  const char *user;
  int ctrl;

  ctrl = _pam_parse_args (pamh, flags, argc, argv);

  void_str = NULL;
  int retval = pam_get_item (pamh, PAM_USER, &void_str);
  if (retval != PAM_SUCCESS || void_str == NULL || strlen (void_str) == 0)
    {
      if (!(ctrl & LASTLOG2_QUIET))
	pam_syslog (pamh, LOG_NOTICE, "User unknown");
      return PAM_USER_UNKNOWN;
    }
  user = void_str;

  /* verify the user exists */
  pwd = pam_modutil_getpwnam (pamh, user);
  if (pwd == NULL)
    {
      if (ctrl & LASTLOG2_DEBUG)
	pam_syslog (pamh, LOG_DEBUG, "Couldn't find user %s",
		    (const char *)user);
      return PAM_USER_UNKNOWN;
    }

  if (ctrl & LASTLOG2_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "user=%s", user);

  show_lastlogin (pamh, ctrl, user);

  return write_login_data (pamh, ctrl, user);
}

int
pam_sm_close_session (pam_handle_t *pamh __attribute__((__unused__)),
		      int flags __attribute__((__unused__)),
		      int argc __attribute__((__unused__)),
		      const char **argv __attribute__((__unused__)))
{
  return PAM_SUCCESS;
}
