CXX ?= g++
CXXFLAGS ?= -Wall -Wextra -Werror -std=c++17 -O3 -ggdb3 -fstack-protector-strong -fsanitize=address,undefined

BIN = callback
DEP = callback.d

all: $(BIN)

clean:
	$(RM) $(DEP) $(BIN)

callback: callback.hpp
	$(CXX) $(CPPFLAGS) -DTEST -x c++ $(CXXFLAGS) -MD -MT $@ -MF $(@).d -o $@ $<

.PHONY: all clean

-include $(DEP)
