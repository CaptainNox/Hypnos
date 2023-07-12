cmake_minimum_required(VERSION 3.25)
project(Hypnos C)

set(CMAKE_C_STANDARD 11)

add_executable(Hypnos main.c src/includes/inject.h src/includes/sysgate.h src/inject.c src/main.c src/sysgate.c)
