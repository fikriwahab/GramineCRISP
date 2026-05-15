crisp_test_inc = include_directories(
    '.',
    '..',
    '../libos/src',
    '../libos/include',
    '../libos/include/arch/x86_64',
    '../pal/include',
    '../pal/include/pal',
    '../pal/include/elf',
    '../pal/include/arch/x86_64',
    '../pal/include/arch/x86_64/linux',
    '../common/include',
    '../common/include/arch/x86_64',
    '../common/src/protected_files',
    '../subprojects/uthash-2.1.0/src',
    '../subprojects/tomlc99-208203af46bdbdb29ba199660ed78d09c220b6c5',
    '../subprojects/mbedtls-3.6.3/include',
    '../subprojects/mbedtls-3.6.3/mbedtls-3.6.3/include',
)

crisp_test_cargs = [
    '-DIN_LIBOS',
    '-ffreestanding',
    '-mfxsr',
    '-mxsave',
    '-DMBEDTLS_CONFIG_FILE="mbedtls/config-pal.h"',
    '-DCRYPTO_USE_MBEDTLS',
]

crisp_init_test = executable(
    'test_crisp_init',
    [
        'test_crisp_init.c',
        '../libos/src/crisp/crisp_init.c',
    ],
    include_directories: crisp_test_inc,
    c_args: crisp_test_cargs,
    install: false,
)

test('crisp-session9-init', crisp_init_test, args: ['all'])

crisp_checker_test = executable(
    'test_crisp_checker_api',
    'test_crisp_checker_api.c',
    install: false,
)

test('crisp-session10-checker', crisp_checker_test, args: ['all'])

crisp_config_test = executable(
    'test_crisp_config',
    [
        'test_crisp_config.c',
        '../libos/src/crisp/crisp_config.c',
        '../common/src/string/toml_utils.c',
        tomlc99_src,
    ],
    include_directories: crisp_test_inc,
    c_args: crisp_test_cargs,
    install: false,
)

test('crisp-config-parse', crisp_config_test, args: ['all'])
