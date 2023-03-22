# This file builds and runs the unit tests

libdl = cc.find_library('dl')


tst_dlopen_exe = executable('tst-dlopen', 'tst-dlopen.c', dependencies : libdl)
test('tst-dlopen', tst_dlopen_exe, args : ['pam_lastlog2.so'])

tst_y2038_64bit_time_t = executable('tst-y2038-64bit-time_t', 'tst-y2038-64bit-time_t.c')
test('tst-y2038-64bit-time_t', tst_y2038_64bit_time_t)

tst_y2038_sqlite3_time = executable('tst-y2038-sqlite3-time', 'tst-y2038-sqlite3-time.c', include_directories : inc, link_with : liblastlog2)
test('tst-y2038-sqlite3-time', tst_y2038_sqlite3_time)

tst_pam_lastlog2_output = executable('tst-pam_lastlog2-output',
			'tst-pam_lastlog2-output.c',
			include_directories : inc,
			link_with : liblastlog2)
#test('tst-pam_lastlog2-output', tst_pam_lastlog2_output)
test('tst-pam_lastlog2-output', find_program('tst-pam_lastlog2-output.sh'))

tst_rename_user = executable('tst-rename-user',
                        'tst-rename-user.c',
                        include_directories : inc,
                        link_with : liblastlog2)
test('tst-rename-user', tst_rename_user)

tst_remove_entry = executable('tst-remove-entry',
                        'tst-remove-entry.c',
                        include_directories : inc,
                        link_with : liblastlog2)
test('tst-remove-entry', tst_remove_entry)

tst_write_read_user = executable('tst-write-read-user',
                        'tst-write-read-user.c',
                        include_directories : inc,
                        link_with : liblastlog2)
test('tst-write-read-user', tst_write_read_user)

