cmake_minimum_required(VERSION 3.12)
project(nfc_eventd C)

set(CMAKE_C_STANDARD 11)

include_directories(/Users/koteeq/Projects/Github/libnfc/include)
include_directories(.)
include_directories(src)
include_directories(src/debug)
include_directories(src/modules)
include_directories(src/nfcconf)

add_executable(nfc_eventd
        src/debug/debug.c
        src/debug/debug.h
        src/debug/nfc-utils.c
        src/debug/nfc-utils.h
        src/modules/nem_common.h
        src/modules/nem_execute.c
        src/modules/nem_execute.h
        src/modules/nem_plantain.c
        src/modules/nem_plantain.h
        src/nfcconf/internal.h
        src/nfcconf/nfcconf.c
        src/nfcconf/nfcconf.h
        src/nfcconf/nfclex.c
        src/nfcconf/parse.c
        src/nfcconf/write.c
        src/nfc-eventd.c
        src/types.h)
