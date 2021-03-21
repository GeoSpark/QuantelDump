*-----------------------------------------------------------
* Title      :
* Written by :
* Date       :
* Description:
*-----------------------------------------------------------
    ORG    $1000
    
machine_sn equ 10000
password: DC.B 'VVUE2QDXV3RQQW6TRQ'

;machine_sn equ 13464
;password: DC.B '2DM58M7TN37Q4P25ZY'

p_is_font equ $fc0
p_serial_number equ $fd0
p_options equ $fe0
p_expiry equ $ff0

START:
; Input parameters
    move.l #machine_sn, -(a7)
    move.l #password, -(a7)

; Outputs
    move.l #p_is_font, -(a7)
    move.l #p_serial_number, -(a7)
    move.l #p_options, -(a7)
    move.l #p_expiry, -(a7)

    jsr s_decrypt

    bra.l fin


s_decrypt:
    link a6, #-$98           ; S6_DECRYPT:117
    adda.w #$54, a7
    movem.l d0-d7/a0-a4, -(a7)
    lea.l integer_multiply, a2
    lea.l -$18(a6), a3
    lea.l eor, a4
    movea.l $10(a6), a0        ; S6_DECRYPT:118
    move.l #$ffff, (a0)
    movea.l $c(a6), a0         ; S6_DECRYPT:119
    move.l #$ffff, (a0)
    movea.l $8(a6), a0         ; S6_DECRYPT:128
    move.l #$ffff, (a0)
    moveq #$0, d6               ; S6_DECRYPT:129
    movea.l $18(a6), a0
    moveq #$0, d7               ; S6_DECRYPT:130
    ; Take each byte from a0_array, look up into bitfield table_$4638ee, set d6 to true if a bit is 1.
validate_password:
    move.b (a0, d7.l), d0
    andi.l #$ff, d0
    lea.l table_0x004638ee, a1
    move.w d0, d1
    lsr.w #$3, d1
    btst d0, (a1, d1.w)
    bne.b char_ok
    moveq #$1, d6
char_ok:
    addq.l #$1, d7
    cmpi.l #$11, d7
    bls.b validate_password

; If 0 then return.
    tst.b d6
    beq.b pwchars_are_valid
    movea.l $14(a6), a0
    move.b #$1, (a0)
    bra.w decrypt_exit
pwchars_are_valid:
    clr.l -$20(a6)
    movea.l #password, a0
    moveq #$0, d7
; Descramble password
descramble:
    move.l d7, d0
    lsl.l #$1, d0
    lea.l table_0x0046386a, a1
    move.w (a1, d0.l), d1
    andi.l #$ffff, d1
    cmpi.l #$11, d1
    bls.b descr_bounds_check
    trap #$f
descr_bounds_check:
    move.b (a0, d1.l), (-$14, a6, d7.l)
    addq.l #$1, d7
    cmpi.l #$11, d7
    bls.b descramble

; Smush bits together
    moveq #$0, d7
smush_loop_1:
    subq.w #$4, a7
    clr.l d0
    move.b (-$14, a6, d7.l), d0
    subi.w #$30, d0
    chk.w #$2a, d0
    asl.w #$1, d0

; Look up into array of 42 words
    lea.l table_0x00463814, a0
    move.w (a0, d0.w), d1
    ext.l d1

; xor value with a6_-#$20 mask off #$1f and add the result back to a6_-#$20
    move.l d1, -(a7)
    move.l -$20(a6), -(a7)
    jsr (a4)                    ; eor
    addq.w #$8, a7
    move.l (a7)+, d5
    andi.l #$1f, d5
    
    add.l d5, -$20(a6)
    move.l d7, d4
    moveq #$5, d3
    jsr (a2)                    ; safe_integer_multiply d3 = d4 * d3

    moveq #$0, d6
smush_loop_2:
    move.l d4, d0
    add.l d6, d0
    movea.l a6, a0
    ror.l #$3, d0
    adda.w d0, a0
    swap d0
    rol.w #$3, d0
    move.w #$ff7f, d1
    ror.w d0, d1
    and.b d1, -$44(a0)
    subq.w #$4, a7
    moveq #$4, d1
    sub.l d6, d1
    subi.l #$ffff8000, d1
    cmpi.l #$ffff, d1
    bls.b smush_bounds_check
    trap #$f
smush_bounds_check:
    addi.l #$ffff8000, d1
    move.w d1, -(a7)
    move.w #$1, -(a7)
    move.l d5, -(a7)
    jsr GET_BITS
    addq.w #$8, a7
    tst.l (a7)+
    beq.b smush_bit_set
    move.b #$80, d1
    lsr.b d0, d1
    or.b d1, -$44(a0)
smush_bit_set:
    addq.l #$1, d6
    cmpi.l #$4, d6
    bls.b smush_loop_2
    addq.l #$1, d7
    cmpi.l #$f, d7
    bls.w smush_loop_1

; line 179
    movea.l $14(a6), a0
    clr.b (a0)
    clr.l d0
; Take last char of descrambled password [a], index into the scramble table and multiply it by 32, store in d0
    move.b -$3(a6), d0
    subi.w #$30, d0
    chk.w #$2a, d0
    asl.w #$1, d0
    lea.l table_0x00463814, a1
    move.w (a1, d0.w), d0
    asl.w #$5, d0

; Take next-to-last char of descrambled password [b], index into the scamble table and add it to the previous result in d0, store in d0
    clr.l d1
    move.b -$4(a6), d1
    subi.w #$30, d1
    chk.w #$2a, d1
    asl.w #$1, d1
    lea.l table_0x00463814, a1
    add.w (a1, d1.w), d0

; Compare d0 with long -#$20(a6) [c], set is_invalid to 1 if they're not equal
    ext.l d0
    cmp.l -$20(a6), d0
    beq.b cs_valid
    addq.b #$1, (a0)
    
; line 180
; Xor long at param_d[d] with #$cc995533, store back to itself
cs_valid:
    subq.w #$4, a7
    move.l $1c(a6), -(a7)
    move.l #$cc995533, -(a7)
    jsr (a4)                    ; eor
    addq.w #$8, a7
    move.l (a7)+, $1c(a6)

; line 181
; Take just the two MSBs of d5
    move.l $1c(a6), d5
    lsr.l #$8, d5
    lsr.l #$8, d5

; Add #$10dda and mask LS word
    addi.l #$10dda, d5
    andi.l #$ffff, d5

; line 182
; Take result of XOR mask off lower word, add #$10dda and mask again, storing it at address a3
    move.l $1c(a6), (a3)
    andi.l #$ffff, (a3)
    addi.l #$10dda, (a3)
    andi.l #$ffff, (a3)

; line 183
; Multiply d5 by #$8301
    move.l #$8301, d4
    move.l d5, d3
    jsr (a2)                    ; safe_integer_multiply d3 = d4 * d3; d4 = d3
    subq.w #$4, a7

; Add #$dbed to result and mask, store in d4
    addi.l #$dbed, d4
    andi.l #$ffff, d4

; XOR d4 with contents of (a3), store in d6
    move.l d4, -(a7)
    move.l (a3), -(a7)
    jsr (a4)                    ; eor
    addq.w #$8, a7
    move.l (a7)+, d6

; line 188
; Multiply contents of (a3) by #$501b, add to d6 and store in d4
    move.l #$501b, d4
    move.l (a3), d3
    jsr (a2)                    ; safe_integer_multiply d3 = d4 * d3
    subq.w #$4, a7
    add.l d6, d4

; XOR d4 and d5, store in d6
    move.l d4, -(a7)
    move.l d5, -(a7)
    jsr (a4)                    ; eor
    addq.w #$8, a7
    move.l (a7)+, d6

; line 193
    moveq #$0, d7
swizzle_loop:
    move.l d7, d4
    moveq #$3, d3
    jsr (a2)                    ; safe_integer_multiply d3 = d4 * d3
    subq.w #$8, a7

; Copy the d7-th byte from the smushed array onto the stack, and make room on the stack for a long, which is the result of the GET_BITS call I think
    clr.l d0
    move.b (-$44, a6, d7.l), d0
    move.l d0, -(a7)
    subq.w #$4, a7

; Multiply d7 by two and store in d0
    move.l d7, d0
    lsl.l #$1, d0
    subi.l #$ffff8000, d0
    cmpi.l #$ffff, d0
    bls.b bounds_check_2
    trap #$f
bounds_check_2:
    addi.l #$ffff8000, d0
    move.w d0, -(a7) ; Offset
    move.w #$8, -(a7) ; Num bits
    move.l d6, -(a7) ; Value
    jsr GET_BITS
    addq.w #$8, a7
    jsr (a4)                    ; eor
    addq.w #$2, a7
    subi.l #$ffff8000, d4
    cmpi.l #$ffff, d4
    bls.b bounds_check_3
    trap #$f
bounds_check_3:
    addi.l #$ffff8000, d4
   
    move.w d4, -(a7) ; Offset
    move.w #$3, -(a7) ; Num bits
    move.l d6, -(a7) ; Value
    jsr GET_BITS
    addq.w #$8, a7
   
    move.l (a7)+, d0
    cmpi.l #$ffff, d0
    bls.b bounds_check_4
    trap #$f
bounds_check_4:
    move.w d0, (a7)
    jsr ror
    addq.w #$6, a7
    move.l (a7)+, d0
    cmpi.l #$ff, d0
    bls.b bounds_check_5
    trap #$f
bounds_check_5:
    move.b d0, (-$44, a6, d7.l)
    
    addq.l #$1, d7
    cmpi.l #$9, d7
    bls.w swizzle_loop

    moveq #$0, d7
bit_loop:
    btst #$0, d7
    beq.b even
    movea.l a6, a0
    move.l d7, d0
    ror.l #$3, d0
    adda.w d0, a0
    swap d0
    rol.w #$3, d0
    move.l d7, d4
    moveq #$1d, d3
    jsr (a2)                    ; safe_integer_multiply d3 = d4 * d3
    moveq #$50, d3
    jsr div_mod
    neg.w d3
    addi.w #$4f, d3
    andi.l #$ffff, d3
    movea.l a6, a1
    ror.l #$3, d3
    adda.w d3, a1
    swap d3
    rol.w #$3, d3
    move.b -$44(a1), d1
    lsl.b d3, d1
    lsr.b #$7, d1
    bra.b tail
even:
    movea.l a6, a0
    move.l d7, d0
    ror.l #$3, d0
    adda.w d0, a0
    swap d0
    rol.w #$3, d0
    move.l d7, d4
    moveq #$1d, d3
    jsr (a2)                    ; safe_integer_multiply d3 = d4 * d3
    moveq #$50, d3
    jsr div_mod
    neg.w d3
    addi.w #$4f, d3
    andi.l #$ffff, d3
    movea.l a6, a1
    ror.l #$3, d3
    adda.w d3, a1
    swap d3
    rol.w #$3, d3
    move.b -$44(a1), d1
    lsl.b d3, d1
    lsr.b #$7, d1
    neg.b d1
    addq.b #$1, d1
tail:
    move.w #$ff7f, d2
    ror.w d0, d2
    and.b d2, -$3a(a0)
    andi.b #$1, d1
    lsl.b #$7, d1
    lsr.b d0, d1
    or.b d1, -$3a(a0)
    addq.l #$1, d7
    cmpi.l #$4f, d7
    bls.w bit_loop


    movea.l $10(a6), a0
    move.l -$3a(a6), (a0)

    movea.l $0c(a6), a0
    move.l -$36(a6), (a0)

    movea.l $08(a6), a0
    clr.l d0
    move.w -$32(a6), d0
    move.l d0, (a0)

    movem.l (a7)+, d0-d7/a0-a4
    unlk a6

decrypt_exit:
    rts




div_mod:
    cmp.l d3, d4
    bcs.b x_label_2
    swap d3
    tst.w d3
    beq.b x_label_4
    swap d3
    bmi.b x_label_3
    movem.l d0-d2, -(a7)
    moveq #$ff, d0
x_loop_1:
    add.l d3, d3
    dbmi d0, x_loop_1
    moveq #$10, d1
    add.w d0, d1
    move.w d4, d2
    neg.l d0
    lsl.w d0, d2
    lsr.l d1, d4
    swap d3
    divu.w d3, d4
    swap d3
    move.w d4, d1
    move.w d2, d4
    move.w d1, d2
    mulu.w d3, d2
    sub.l d2, d4
    bcc.b x_label_1
    subq.w #$1, d1
    add.l d3, d4
    bcs.b x_label_1
    subq.w #$1, d1
    add.l d3, d4
x_label_1:
    move.l d4, d3
    lsr.l d0, d3
    move.l d1, d4
    movem.l (a7)+, d0-d2
    rts
x_label_2:
    move.l d4, d3
    moveq #$0, d4
    rts
x_label_3:
    sub.l d3, d4
    move.l d4, d3
    moveq #$1, d4
    rts
x_label_4:
    swap d3
    trapv  ; beq.w 0x406bca
    move.w d4, -(a7)
    clr.w d4
    swap d4
    beq.b x_label_5
    divu.w d3, d4
    swap d3
    move.w d4, d3
    swap d3
x_label_5:
    move.w (a7)+, d4
    divu.w d3, d4
    move.w d4, d3
    clr.w d4
    swap d4
    exg.l d3, d4
    tst.l d4
    rts

integer_multiply:
    cmp.l d4, d3    
    bcc.b label2
    exg.l d3, d4
label2:    
    move.l d4, -(a7)
    mulu.w d3, d4   
    move.w (a7)+, d3
    swap d3         
    bne.b label3
    addq.w #$2, a7  
    bra.b label4
label3:
    mulu.w (a7)+, d3
    swap d3         
    tst.w d3        
    add.l d3, d4    
label4:
    move.l d4, d3   
    rts

GET_BITS:
    link a6, #$0
    movem.l d0-d1, -(a7)
    move.l $8(a6), d0
    move.w $e(a6), d1
    asr.l d1, d0
    move.w $c(a6), d1
    asl.w #$2, d1
    lea BITS_TABLE, a5
    and.l (a5, d1.w), d0
    move.l d0, $10(a6)
    movem.l (a7)+, d0-d1
    unlk a6
    rts

eor:
    link a6, #$0
    movem.l d0-d1, -(a7)
    move.l $c(a6), d0
    move.l $8(a6), d1
    eor.l d1, d0
    move.l d0, $10(a6)
    movem.l (a7)+, d0-d1
    unlk a6
    rts

ror:
    link a6, #0
    movem.l d0-d1, -(a7)
    move.l $a(a6), d0
    move.w $8(a6), d1
    ror.b d1, d0
    move.l d0, $e(a6)
    movem.l (a7)+, d0-d1
    unlk a6
    rts

fin:
    nop
    SIMHALT             ; halt simulator

* Put variables and constants here


table_0x00463814
    DC.W $00ff
    DC.W $00ff
    DC.W $0003
    DC.W $0007
    DC.W $000b
    DC.W $000f
    DC.W $0013
    DC.W $0017
    DC.W $001b
    DC.W $001f
    DC.W $00ff
    DC.W $00ff
    DC.W $00ff
    DC.W $00ff
    DC.W $00ff
    DC.W $00ff
    DC.W $00ff
    DC.W $0000
    DC.W $0004
    DC.W $0008
    DC.W $000c
    DC.W $0010
    DC.W $0014
    DC.W $0018
    DC.W $001c
    DC.W $00ff
    DC.W $0001
    DC.W $0005
    DC.W $0009
    DC.W $000d
    DC.W $0011
    DC.W $00ff
    DC.W $0015
    DC.W $0019
    DC.W $001d
    DC.W $0002
    DC.W $0006
    DC.W $000a
    DC.W $000e
    DC.W $0012
    DC.W $0016
    DC.W $001a
    DC.W $001e

table_0x0046386a
    DC.W $0007
    DC.W $000d
    DC.W $0002
    DC.W $000a
    DC.W $0006
    DC.W $0000
    DC.W $0010
    DC.W $000b
    DC.W $0011
    DC.W $0005
    DC.W $000f
    DC.W $0001
    DC.W $0008
    DC.W $000c
    DC.W $0003
    DC.W $000e
    DC.W $0004
    DC.W $0009

table_0x004638ee
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $fc03
    DC.W $fe7d
    DC.W $ff07
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $0000
    DC.W $0000

BITS_TABLE:
    DC.L $00000000
    DC.L $00000001
    DC.L $00000003
    DC.L $00000007
    DC.L $0000000f
    DC.L $0000001f
    DC.L $0000003f
    DC.L $0000007f
    DC.L $000000ff
    DC.L $000001ff
    DC.L $000003ff
    DC.L $000007ff
    DC.L $00000fff
    DC.L $00001fff
    DC.L $00003fff
    DC.L $00007fff
    DC.L $0000ffff
    DC.L $0001ffff
    DC.L $0003ffff
    DC.L $0007ffff
    DC.L $000fffff
    DC.L $001fffff
    DC.L $003fffff
    DC.L $007fffff
    DC.L $00ffffff
    DC.L $01ffffff
    DC.L $03ffffff
    DC.L $07ffffff
    DC.L $0fffffff
    DC.L $1fffffff
    DC.L $3fffffff
    DC.L $7fffffff
    DC.L $ffffffff


    END    START        ; last line of source

*~Font name~Courier New~
*~Font size~10~
*~Tab type~1~
*~Tab size~4~
