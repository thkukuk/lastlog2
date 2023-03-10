project(
  'lastlog2',
  'c',
  meson_version : '>= 0.49.0',
  default_options : [
                  'prefix=/usr',
                  'sysconfdir=/etc',
                  'localstatedir=/var',
                  'buildtype=debugoptimized',
  		  'default_library=shared',
		  'b_pie=true',
		  'warning_level=3',],
  license : ['BSD-2-Clause',],
  version : '0.0.1',
)

cc = meson.get_compiler('c')
inc = include_directories('include')

add_project_arguments(['-D_GNU_SOURCE=1',
		       '-DXTSTRINGDEFINES',
		       '-D_FORTIFY_SOURCE=2'], language : 'c')

possible_cc_flags = [
                  '-Dwerror=true',
                  '-flto=auto',
                  '-ffat-lto-objects',
		  '-fstack-protector-strong',
		  '-funwind-tables',
		  '-fasynchronous-unwind-tables',
		  '-fstack-clash-protection',
		  '-Werror=return-type',
		  '-Wbad-function-cast',
		  '-Wcast-align',
		  '-Wcast-qual',
		  '-Winline',
		  '-Wmissing-declarations',
		  '-Wmissing-prototypes',
		  '-Wnested-externs',
		  '-Wshadow',
		  '-Wstrict-prototypes',
		  '-Wundef',
		  ]
add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')

fs = import('fs')
if get_option('split-usr') == 'auto'
        split_usr = not fs.is_symlink('/bin')
else
        split_usr = get_option('split-usr') == 'true'
endif

rootprefixdir = get_option('rootprefix')
rootprefix_default = split_usr ? '/' : '/usr'
if rootprefixdir == ''
        rootprefixdir = rootprefix_default
endif

rootlibdir = get_option('rootlibdir')
if rootlibdir == ''
        # This will be a relative path if libdir is in prefix.
        rootlibdir = get_option('libdir')
endif
if not rootlibdir.startswith('/')
        # If we have a relative path, add rootprefixdir to the front.
        rootlibdir = rootprefixdir / rootlibdir
endif

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
        pamlibdir = rootlibdir / 'security'
endif

libpam = cc.find_library('pam')
libsqlite3 = cc.find_library('sqlite3')

pam_lastlog2_map = 'src/pam_lastlog2.map'
pam_lastlog2_c = files('src/pam_lastlog2.c')

version_flag = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), pam_lastlog2_map)

pam_lastlog2 = shared_library(
  'pam_lastlog2',
  pam_lastlog2_c,
  name_prefix : '',
  include_directories : inc,
  link_args : ['-shared', version_flag,],
  link_depends : pam_lastlog2_map,
  dependencies : [libpam, libsqlite3],
  install : true,
  install_dir : pamlibdir
)

lastlog2_c = ['src/lastlog2.c']

executable('lastlog2', 
           lastlog2_c, 
           include_directories : inc,
           dependencies : libsqlite3)

# Unit tests
subdir('tests')

# documentation
#subdir('doc')
