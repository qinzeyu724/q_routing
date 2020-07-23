BMV2_SWITCH_EXE = simple_switch_grpc
NO_P4 = true
P4C_ARGS = --p4runtime-file $(basename $@).p4info --p4runtime-format text

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

TOPO = topology.json
LOOPTOPO = loop_topology.json
RANDTOPO = random_topology.json
EASYTOPO = easy_topology.json
P4C = p4c-bm2-ss
RUN_SCRIPT = ../../utils/run_exercise.py

source := $(wildcard *.p4)
outfile := $(source:.p4=.json)

compiled_json := $(BUILD_DIR)/$(outfile)

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(compiled_json)
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

all: run

run: 
	sudo python $(RUN_SCRIPT) -t $(TOPO) $(run_args)

run_loop:
	sudo python $(RUN_SCRIPT) -t $(LOOPTOPO) $(run_args)

run_rand:
	sudo python $(RUN_SCRIPT) -t $(RANDTOPO) $(run_args)

run_easy:
	sudo python $(RUN_SCRIPT) -t $(EASYTOPO) $(run_args)

stop:
	sudo mn -c

build: dirs $(compiled_json)

$(BUILD_DIR)/%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)