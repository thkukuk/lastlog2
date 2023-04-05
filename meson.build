project(
  'lastlog2',
  'c',
  meson_version : '>= 0.53.0',
  default_options : [
                  'prefix=/usr',
                  'sysconfdir=/etc',
                  'localstatedir=/var',
                  'buildtype=debugoptimized',
  		  'default_library=shared',
		  'b_pie=true',
		  'warning_level=2',],
  license : ['BSD-2-Clause',],
  version : '0.7.0',
)

cc = meson.get_compiler('c')
pkg = import('pkgconfig')
inc = include_directories('include')

add_project_arguments(['-D_GNU_SOURCE=1',
		       '-DXTSTRINGDEFINES',
		       '-D_FORTIFY_SOURCE=2',
                       '-D_FILE_OFFSET_BITS=64',
                       '-D_TIME_BITS=64',
                       '-DPROJECT_VERSION="@0@"'.format(meson.project_version()) ], language : 'c')

possible_cc_flags = [
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
                  '-Wformat-security',
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

# Meson ignores the preceding arguments when joining paths if an absolute
# component is encountered, so this should canonicalize various paths when they
# are absolute or relative.
prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
if prefixdir != rootprefixdir and rootprefixdir != '/' and not prefixdir.strip('/').startswith(rootprefixdir.strip('/') + '/')
        error('Prefix is not below root prefix (now rootprefix=@0@ prefix=@1@)'.format(rootprefixdir, prefixdir))
endif
systemunitdir = prefixdir / 'lib/systemd/system'
tmpfilesdir = prefixdir / 'lib/tmpfiles.d'

libpam = cc.find_library('pam')
libsqlite3 = cc.find_library('sqlite3')

liblastlog2_c = files('lib/lastlog2.c')
liblastlog2_map = 'lib/liblastlog2.map'
liblastlog2_map_version = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), liblastlog2_map)

pam_lastlog2_c = files('src/pam_lastlog2.c')
pam_lastlog2_map = 'src/pam_lastlog2.map'
pam_lastlog2_map_version = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), pam_lastlog2_map)

liblastlog2 = shared_library(
  'lastlog2',
  liblastlog2_c,
  include_directories : inc,
  link_args : ['-shared',
               liblastlog2_map_version],
  link_depends : liblastlog2_map,
  dependencies : [libsqlite3],
  install : true,
  soversion : '1'
)
install_headers('include/lastlog2.h')

pkg.generate(
  liblastlog2,
  name : 'liblastlog2',
  description : 'library to manage last login data',
  version : meson.project_version(),
)

pam_lastlog2 = shared_library(
  'pam_lastlog2',
  pam_lastlog2_c,
  name_prefix : '',
  include_directories : inc,
  link_args : ['-shared', pam_lastlog2_map_version],
  link_depends : pam_lastlog2_map,
  link_with : liblastlog2,
  dependencies : [libpam],
  install : true,
  install_dir : pamlibdir
)

lastlog2_c = ['src/lastlog2.c']

executable('lastlog2', 
           lastlog2_c, 
           include_directories : inc,
           link_with : liblastlog2,
           install : true)

subdir('tmpfiles.d')
subdir('units')

# Unit tests
subdir('tests')

# Manual pages
subdir('man')
