# B — Buffer Overflow (Defensive Perspective)

## Beginner Explanation
A buffer overflow happens when a program tries to put more data into a container than it can hold. Imagine filling a cup with water — if you pour too much, it spills over onto the table. In memory, this "spill" can overwrite critical data, including the instruction pointer that controls what code runs next.

## Technical Deep Dive

### How Buffer Overflows Work
```c
// Vulnerable C code — strcpy does not check buffer size
void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // If input > 64 bytes, overflow occurs
}

// If attacker passes 100 bytes, the extra 36 bytes overwrite:
// - Saved frame pointer
// - Return address (attacker can redirect execution)
```

### Defensive Coding Practices
```c
// Safe alternative — strncpy limits copy to buffer size
strncpy(buffer, input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination

// Even better — snprintf
snprintf(buffer, sizeof(buffer), "%s", input);

// In C++, use std::string instead of char arrays entirely
```

### OS-Level Protections
| Protection | Mechanism | Bypass Difficulty |
|------------|-----------|------------------|
| **ASLR** (Address Space Layout Randomization) | Randomizes memory addresses at runtime | Medium (info leak needed) |
| **DEP/NX** (Data Execution Prevention / No-Execute) | Marks data pages non-executable | Medium (ROP chains bypass it) |
| **Stack Canaries** | Places random value before return address; checks before return | Medium (format string leaks) |
| **SafeStack** (LLVM) | Separates control data from regular data stack | High |
| **CFI** (Control Flow Integrity) | Restricts valid jump targets | High |

### Checking ASLR on Linux
```bash
# Check ASLR status
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = partial, 2 = full (recommended)

# Enable full ASLR
sysctl -w kernel.randomize_va_space=2
echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
```

### Checking for Executable Stack (Linux)
```bash
# Check if binary has NX (non-executable stack) enabled
checksec --file=./binary
# NX enabled: yes  ← good
# NX enabled: no   ← vulnerable
```

## Real-World Relevance
**EternalBlue (MS17-010, 2017):** The NSA exploit that enabled WannaCry and NotPetya was a buffer overflow in Windows SMBv1. It allowed remote code execution without authentication on millions of unpatched Windows systems. The Principle of Least Privilege + network segmentation + timely patching would have dramatically limited its impact.

## Defensive Measures
1. Compile all code with stack protection: `gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2`
2. Enable ASLR system-wide
3. Mark stacks non-executable (NX/DEP)
4. Use memory-safe languages (Rust, Go) for new projects where feasible
5. Apply security patches promptly — many buffer overflows are in known-vulnerable components
6. Use fuzzing during development to find buffer overflows before attackers do

## Practice Challenge
1. In a lab VM: Write a simple C program with a fixed-size buffer and strcpy.
2. Compile with stack protector disabled: `gcc -fno-stack-protector -z execstack -o vuln vuln.c`
3. Check the binary with `checksec`.
4. Now recompile with protections enabled and compare checksec output.
5. Document what each protection flag enables.
