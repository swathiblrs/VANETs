CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic

.PHONY: all run clean

all: build/vanet_sim

build/vanet_sim: vanet_sim.cpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) $< -o $@

run: build/vanet_sim
	./build/vanet_sim

clean:
	rm -rf build
