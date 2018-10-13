AFL_CXX ?= afl-g++
CXX ?= g++
CPPFLAGS ?= -isystem $(HOME)/git/GSL/include
CXXFLAGS ?= -Wall -Wextra -Werror -std=c++17 -O3 -ggdb3 -fstack-protector-strong -fsanitize=address,undefined

BIN = callback dns-test dns-test-afl
dns_test_SRC = dns-test.cpp dns.cpp
DEP = callback.d $(dns_test_SRC:.cpp=.d)
OBJ = $(dns_test_SRC:.cpp=.o) $(dns_test_SRC:.cpp=.afl.o)
TEST_CASES_BIN = $(patsubst test-cases/%.bm,test-cases-bin/%.bin,$(wildcard test-cases/*.bm))

all: $(BIN) $(TEST_CASES_BIN)

clean:
	$(RM) $(DEP) $(OBJ) $(BIN) $(TEST_CASES_BIN)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MD -MT $@ -MF $(@:.o=.d) -o $@ -c $<

%.afl.o: %.cpp
	AFL_HARDEN=1 $(AFL_CXX) $(CPPFLAGS) $(CXXFLAGS) -MD -MT $@ -MF $(@:.afl.o=.d) -o $@ -c $<

callback: callback.hpp
	$(CXX) $(CPPFLAGS) -DTEST -x c++ $(CXXFLAGS) -MD -MT $@ -MF $(@).d -o $@ $<

test-cases-bin:
	mkdir test-cases-bin

test-cases-bin/%.bin: test-cases/%.bm test-cases-bin
	binmake $< $@

dns-test: $(dns_test_SRC:.cpp=.o)
	$(CXX) $(CXXFLAGS) -o $@ $^

dns-test-afl: $(dns_test_SRC:.cpp=.afl.o)
	AFL_HARDEN=1 $(AFL_CXX) $(CXXFLAGS) -o $@ $^

.PHONY: all clean

-include $(DEP)
