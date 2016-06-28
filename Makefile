DEPS = src
PHONY = $(DEPS) clean mrproper

all: $(DEPS)
	mv src/canny .

$(DEPS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

clean: $(DEPS)

mrproper: $(DEPS)
	rm -rf canny *~

.PHONY: $(PHONY)
