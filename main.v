`timescale 1ns / 1ps

module AES_Decrypter(CipherText, key, PlainText);  
    input wire[127:0] CipherText,key;          
    output reg [127:0] PlainText;
     // Add Round Key Transformation
    function [127:0] Add_Round_key(input [127:0] State,input [127:0]  Round_key);
        begin
        Add_Round_key = State ^ Round_key;
        end
    endfunction 
    
    // Inverse Shift Row Transformation
    function [127 : 0] Inv_ShiftRow(input [127 : 0] state);
        reg [31 : 0] c0, c1, c2, c3;
        reg [31 : 0] sc0, sc1, sc2, sc3;
        begin
            c0 = state[127 : 096];
            c1 = state[095 : 064];
            c2 = state[063 : 032];
            c3 = state[031 : 000];
    
            sc0 = {c0[31 : 24], c3[23 : 16], c2[15 : 08], c1[07 : 00]};
            sc1 = {c1[31 : 24], c0[23 : 16], c3[15 : 08], c2[07 : 00]};
            sc2 = {c2[31 : 24], c1[23 : 16], c0[15 : 08], c3[07 : 00]};
            sc3 = {c3[31 : 24], c2[23 : 16], c1[15 : 08], c0[07 : 00]};
            
            Inv_ShiftRow = {sc0, sc1, sc2, sc3};
        end
    endfunction 

    // Inverse Substitute Bytes Transformation
    function [127:0] InvSubBytes(input [127:0] State);
        integer i;
        reg [7 : 0] inv_sbox [0 : 255];
        begin
            inv_sbox[8'h00] = 8'h52;
            inv_sbox[8'h01] = 8'h09;
            inv_sbox[8'h02] = 8'h6a;
            inv_sbox[8'h03] = 8'hd5;
            inv_sbox[8'h04] = 8'h30;
            inv_sbox[8'h05] = 8'h36;
            inv_sbox[8'h06] = 8'ha5;
            inv_sbox[8'h07] = 8'h38;
            inv_sbox[8'h08] = 8'hbf;
            inv_sbox[8'h09] = 8'h40;
            inv_sbox[8'h0a] = 8'ha3;
            inv_sbox[8'h0b] = 8'h9e;
            inv_sbox[8'h0c] = 8'h81;
            inv_sbox[8'h0d] = 8'hf3;
            inv_sbox[8'h0e] = 8'hd7;
            inv_sbox[8'h0f] = 8'hfb;
            inv_sbox[8'h10] = 8'h7c;
            inv_sbox[8'h11] = 8'he3;
            inv_sbox[8'h12] = 8'h39;
            inv_sbox[8'h13] = 8'h82;
            inv_sbox[8'h14] = 8'h9b;
            inv_sbox[8'h15] = 8'h2f;
            inv_sbox[8'h16] = 8'hff;
            inv_sbox[8'h17] = 8'h87;
            inv_sbox[8'h18] = 8'h34;
            inv_sbox[8'h19] = 8'h8e;
            inv_sbox[8'h1a] = 8'h43;
            inv_sbox[8'h1b] = 8'h44;
            inv_sbox[8'h1c] = 8'hc4;
            inv_sbox[8'h1d] = 8'hde;
            inv_sbox[8'h1e] = 8'he9;
            inv_sbox[8'h1f] = 8'hcb;
            inv_sbox[8'h20] = 8'h54;
            inv_sbox[8'h21] = 8'h7b;
            inv_sbox[8'h22] = 8'h94;
            inv_sbox[8'h23] = 8'h32;
            inv_sbox[8'h24] = 8'ha6;
            inv_sbox[8'h25] = 8'hc2;
            inv_sbox[8'h26] = 8'h23;
            inv_sbox[8'h27] = 8'h3d;
            inv_sbox[8'h28] = 8'hee;
            inv_sbox[8'h29] = 8'h4c;
            inv_sbox[8'h2a] = 8'h95;
            inv_sbox[8'h2b] = 8'h0b;
            inv_sbox[8'h2c] = 8'h42;
            inv_sbox[8'h2d] = 8'hfa;
            inv_sbox[8'h2e] = 8'hc3;
            inv_sbox[8'h2f] = 8'h4e;
            inv_sbox[8'h30] = 8'h08;
            inv_sbox[8'h31] = 8'h2e;
            inv_sbox[8'h32] = 8'ha1;
            inv_sbox[8'h33] = 8'h66;
            inv_sbox[8'h34] = 8'h28;
            inv_sbox[8'h35] = 8'hd9;
            inv_sbox[8'h36] = 8'h24;
            inv_sbox[8'h37] = 8'hb2;
            inv_sbox[8'h38] = 8'h76;
            inv_sbox[8'h39] = 8'h5b;
            inv_sbox[8'h3a] = 8'ha2;
            inv_sbox[8'h3b] = 8'h49;
            inv_sbox[8'h3c] = 8'h6d;
            inv_sbox[8'h3d] = 8'h8b;
            inv_sbox[8'h3e] = 8'hd1;
            inv_sbox[8'h3f] = 8'h25;
            inv_sbox[8'h40] = 8'h72;
            inv_sbox[8'h41] = 8'hf8;
            inv_sbox[8'h42] = 8'hf6;
            inv_sbox[8'h43] = 8'h64;
            inv_sbox[8'h44] = 8'h86;
            inv_sbox[8'h45] = 8'h68;
            inv_sbox[8'h46] = 8'h98;
            inv_sbox[8'h47] = 8'h16;
            inv_sbox[8'h48] = 8'hd4;
            inv_sbox[8'h49] = 8'ha4;
            inv_sbox[8'h4a] = 8'h5c;
            inv_sbox[8'h4b] = 8'hcc;
            inv_sbox[8'h4c] = 8'h5d;
            inv_sbox[8'h4d] = 8'h65;
            inv_sbox[8'h4e] = 8'hb6;
            inv_sbox[8'h4f] = 8'h92;
            inv_sbox[8'h50] = 8'h6c;
            inv_sbox[8'h51] = 8'h70;
            inv_sbox[8'h52] = 8'h48;
            inv_sbox[8'h53] = 8'h50;
            inv_sbox[8'h54] = 8'hfd;
            inv_sbox[8'h55] = 8'hed;
            inv_sbox[8'h56] = 8'hb9;
            inv_sbox[8'h57] = 8'hda;
            inv_sbox[8'h58] = 8'h5e;
            inv_sbox[8'h59] = 8'h15;
            inv_sbox[8'h5a] = 8'h46;
            inv_sbox[8'h5b] = 8'h57;
            inv_sbox[8'h5c] = 8'ha7;
            inv_sbox[8'h5d] = 8'h8d;
            inv_sbox[8'h5e] = 8'h9d;
            inv_sbox[8'h5f] = 8'h84;
            inv_sbox[8'h60] = 8'h90;
            inv_sbox[8'h61] = 8'hd8;
            inv_sbox[8'h62] = 8'hab;
            inv_sbox[8'h63] = 8'h00;
            inv_sbox[8'h64] = 8'h8c;
            inv_sbox[8'h65] = 8'hbc;
            inv_sbox[8'h66] = 8'hd3;
            inv_sbox[8'h67] = 8'h0a;
            inv_sbox[8'h68] = 8'hf7;
            inv_sbox[8'h69] = 8'he4;
            inv_sbox[8'h6a] = 8'h58;
            inv_sbox[8'h6b] = 8'h05;
            inv_sbox[8'h6c] = 8'hb8;
            inv_sbox[8'h6d] = 8'hb3;
            inv_sbox[8'h6e] = 8'h45;
            inv_sbox[8'h6f] = 8'h06;
            inv_sbox[8'h70] = 8'hd0;
            inv_sbox[8'h71] = 8'h2c;
            inv_sbox[8'h72] = 8'h1e;
            inv_sbox[8'h73] = 8'h8f;
            inv_sbox[8'h74] = 8'hca;
            inv_sbox[8'h75] = 8'h3f;
            inv_sbox[8'h76] = 8'h0f;
            inv_sbox[8'h77] = 8'h02;
            inv_sbox[8'h78] = 8'hc1;
            inv_sbox[8'h79] = 8'haf;
            inv_sbox[8'h7a] = 8'hbd;
            inv_sbox[8'h7b] = 8'h03;
            inv_sbox[8'h7c] = 8'h01;
            inv_sbox[8'h7d] = 8'h13;
            inv_sbox[8'h7e] = 8'h8a;
            inv_sbox[8'h7f] = 8'h6b;
            inv_sbox[8'h80] = 8'h3a;
            inv_sbox[8'h81] = 8'h91;
            inv_sbox[8'h82] = 8'h11;
            inv_sbox[8'h83] = 8'h41;
            inv_sbox[8'h84] = 8'h4f;
            inv_sbox[8'h85] = 8'h67;
            inv_sbox[8'h86] = 8'hdc;
            inv_sbox[8'h87] = 8'hea;
            inv_sbox[8'h88] = 8'h97;
            inv_sbox[8'h89] = 8'hf2;
            inv_sbox[8'h8a] = 8'hcf;
            inv_sbox[8'h8b] = 8'hce;
            inv_sbox[8'h8c] = 8'hf0;
            inv_sbox[8'h8d] = 8'hb4;
            inv_sbox[8'h8e] = 8'he6;
            inv_sbox[8'h8f] = 8'h73;
            inv_sbox[8'h90] = 8'h96;
            inv_sbox[8'h91] = 8'hac;
            inv_sbox[8'h92] = 8'h74;
            inv_sbox[8'h93] = 8'h22;
            inv_sbox[8'h94] = 8'he7;
            inv_sbox[8'h95] = 8'had;
            inv_sbox[8'h96] = 8'h35;
            inv_sbox[8'h97] = 8'h85;
            inv_sbox[8'h98] = 8'he2;
            inv_sbox[8'h99] = 8'hf9;
            inv_sbox[8'h9a] = 8'h37;
            inv_sbox[8'h9b] = 8'he8;
            inv_sbox[8'h9c] = 8'h1c;
            inv_sbox[8'h9d] = 8'h75;
            inv_sbox[8'h9e] = 8'hdf;
            inv_sbox[8'h9f] = 8'h6e;
            inv_sbox[8'ha0] = 8'h47;
            inv_sbox[8'ha1] = 8'hf1;
            inv_sbox[8'ha2] = 8'h1a;
            inv_sbox[8'ha3] = 8'h71;
            inv_sbox[8'ha4] = 8'h1d;
            inv_sbox[8'ha5] = 8'h29;
            inv_sbox[8'ha6] = 8'hc5;
            inv_sbox[8'ha7] = 8'h89;
            inv_sbox[8'ha8] = 8'h6f;
            inv_sbox[8'ha9] = 8'hb7;
            inv_sbox[8'haa] = 8'h62;
            inv_sbox[8'hab] = 8'h0e;
            inv_sbox[8'hac] = 8'haa;
            inv_sbox[8'had] = 8'h18;
            inv_sbox[8'hae] = 8'hbe;
            inv_sbox[8'haf] = 8'h1b;
            inv_sbox[8'hb0] = 8'hfc;
            inv_sbox[8'hb1] = 8'h56;
            inv_sbox[8'hb2] = 8'h3e;
            inv_sbox[8'hb3] = 8'h4b;
            inv_sbox[8'hb4] = 8'hc6;
            inv_sbox[8'hb5] = 8'hd2;
            inv_sbox[8'hb6] = 8'h79;
            inv_sbox[8'hb7] = 8'h20;
            inv_sbox[8'hb8] = 8'h9a;
            inv_sbox[8'hb9] = 8'hdb;
            inv_sbox[8'hba] = 8'hc0;
            inv_sbox[8'hbb] = 8'hfe;
            inv_sbox[8'hbc] = 8'h78;
            inv_sbox[8'hbd] = 8'hcd;
            inv_sbox[8'hbe] = 8'h5a;
            inv_sbox[8'hbf] = 8'hf4;
            inv_sbox[8'hc0] = 8'h1f;
            inv_sbox[8'hc1] = 8'hdd;
            inv_sbox[8'hc2] = 8'ha8;
            inv_sbox[8'hc3] = 8'h33;
            inv_sbox[8'hc4] = 8'h88;
            inv_sbox[8'hc5] = 8'h07;
            inv_sbox[8'hc6] = 8'hc7;
            inv_sbox[8'hc7] = 8'h31;
            inv_sbox[8'hc8] = 8'hb1;
            inv_sbox[8'hc9] = 8'h12;
            inv_sbox[8'hca] = 8'h10;
            inv_sbox[8'hcb] = 8'h59;
            inv_sbox[8'hcc] = 8'h27;
            inv_sbox[8'hcd] = 8'h80;
            inv_sbox[8'hce] = 8'hec;
            inv_sbox[8'hcf] = 8'h5f;
            inv_sbox[8'hd0] = 8'h60;
            inv_sbox[8'hd1] = 8'h51;
            inv_sbox[8'hd2] = 8'h7f;
            inv_sbox[8'hd3] = 8'ha9;
            inv_sbox[8'hd4] = 8'h19;
            inv_sbox[8'hd5] = 8'hb5;
            inv_sbox[8'hd6] = 8'h4a;
            inv_sbox[8'hd7] = 8'h0d;
            inv_sbox[8'hd8] = 8'h2d;
            inv_sbox[8'hd9] = 8'he5;
            inv_sbox[8'hda] = 8'h7a;
            inv_sbox[8'hdb] = 8'h9f;
            inv_sbox[8'hdc] = 8'h93;
            inv_sbox[8'hdd] = 8'hc9;
            inv_sbox[8'hde] = 8'h9c;
            inv_sbox[8'hdf] = 8'hef;
            inv_sbox[8'he0] = 8'ha0;
            inv_sbox[8'he1] = 8'he0;
            inv_sbox[8'he2] = 8'h3b;
            inv_sbox[8'he3] = 8'h4d;
            inv_sbox[8'he4] = 8'hae;
            inv_sbox[8'he5] = 8'h2a;
            inv_sbox[8'he6] = 8'hf5;
            inv_sbox[8'he7] = 8'hb0;
            inv_sbox[8'he8] = 8'hc8;
            inv_sbox[8'he9] = 8'heb;
            inv_sbox[8'hea] = 8'hbb;
            inv_sbox[8'heb] = 8'h3c;
            inv_sbox[8'hec] = 8'h83;
            inv_sbox[8'hed] = 8'h53;
            inv_sbox[8'hee] = 8'h99;
            inv_sbox[8'hef] = 8'h61;
            inv_sbox[8'hf0] = 8'h17;
            inv_sbox[8'hf1] = 8'h2b;
            inv_sbox[8'hf2] = 8'h04;
            inv_sbox[8'hf3] = 8'h7e;
            inv_sbox[8'hf4] = 8'hba;
            inv_sbox[8'hf5] = 8'h77;
            inv_sbox[8'hf6] = 8'hd6;
            inv_sbox[8'hf7] = 8'h26;
            inv_sbox[8'hf8] = 8'he1;
            inv_sbox[8'hf9] = 8'h69;
            inv_sbox[8'hfa] = 8'h14;
            inv_sbox[8'hfb] = 8'h63;
            inv_sbox[8'hfc] = 8'h55;
            inv_sbox[8'hfd] = 8'h21;
            inv_sbox[8'hfe] = 8'h0c;
            inv_sbox[8'hff] = 8'h7d;
          
            for(i=0;i<128;i=i+8)
                begin
                InvSubBytes[i+:8] = inv_sbox[State[i+:08]];
                end
        end
    endfunction 
    
    // Inverse Mix Column Transformation
    function [7 : 0] mul_2(input [7 : 0] in);
        begin
            mul_2 = {in[6 : 0], 1'b0} ^ (8'h1b & {8{in[7]}});
        end
    endfunction 
    
    function [7 : 0] mul_4(input [7 : 0] in);
        begin
            mul_4 = mul_2(mul_2(in));
        end
    endfunction 
    
    function [7 : 0] mul_8(input [7 : 0] in);
        begin
            mul_8 = mul_2(mul_4(in));
        end
    endfunction 
    
    function [7 : 0] mul_9(input [7 : 0] in);
        begin
            mul_9 = mul_8(in) ^ in;
        end
    endfunction 
    
    function [7 : 0] mul_11(input [7 : 0] in);
        begin
            mul_11 = mul_8(in) ^ mul_2(in) ^ in;
        end
    endfunction 
    
    function [7 : 0] mul_13(input [7 : 0] in);
        begin
            mul_13 = mul_8(in) ^ mul_4(in) ^ in;
        end
    endfunction 
    
    function [7 : 0] mul_14(input [7 : 0] in);
        begin
            mul_14 = mul_8(in) ^ mul_4(in) ^ mul_2(in);
        end
    endfunction 
    
    function [31 : 0] inv_mixc(input [31 : 0] c);
        reg [7 : 0] b0, b1, b2, b3;
        reg [7 : 0] mb0, mb1, mb2, mb3;
        begin
            b0 = c[31 : 24];
            b1 = c[23 : 16];
            b2 = c[15 : 08];
            b3 = c[07 : 00];
    
            mb0 = mul_14(b0) ^ mul_11(b1) ^ mul_13(b2) ^ mul_9(b3);
            mb1 = mul_9(b0) ^ mul_14(b1) ^ mul_11(b2) ^ mul_13(b3);
            mb2 = mul_13(b0) ^ mul_9(b1) ^ mul_14(b2) ^ mul_11(b3);
            mb3 = mul_11(b0) ^ mul_13(b1) ^ mul_9(b2) ^ mul_14(b3);
    
            inv_mixc = {mb0, mb1, mb2, mb3};
        end
    endfunction
    
    function [127 : 0] inv_mixcolumns(input [127 : 0] info);
        reg [31 : 0] c0, c1, c2, c3;
        reg [31 : 0] cs0, cs1, cs2, cs3;
        begin
            c0 = info[127 : 096];
            c1 = info[095 : 064];
            c2 = info[063 : 032];
            c3 = info[031 : 000];
    
            cs0 = inv_mixc(c0);
            cs1 = inv_mixc(c1);
            cs2 = inv_mixc(c2);
            cs3 = inv_mixc(c3);
    
            inv_mixcolumns = {cs0, cs1, cs2, cs3};
        end
    endfunction
    
    
    // Substitute Byte Transformation
    function [127:0] SubBytes(input [127:0] State);
        integer i;
        reg [7 : 0] sbox [0 : 255];
        begin
            sbox[8'h00] = 8'h63;
            sbox[8'h01] = 8'h7c;
            sbox[8'h02] = 8'h77;
            sbox[8'h03] = 8'h7b;
            sbox[8'h04] = 8'hf2;
            sbox[8'h05] = 8'h6b;
            sbox[8'h06] = 8'h6f;
            sbox[8'h07] = 8'hc5;
            sbox[8'h08] = 8'h30;
            sbox[8'h09] = 8'h01;
            sbox[8'h0a] = 8'h67;
            sbox[8'h0b] = 8'h2b;
            sbox[8'h0c] = 8'hfe;
            sbox[8'h0d] = 8'hd7;
            sbox[8'h0e] = 8'hab;
            sbox[8'h0f] = 8'h76;
            sbox[8'h10] = 8'hca;
            sbox[8'h11] = 8'h82;
            sbox[8'h12] = 8'hc9;
            sbox[8'h13] = 8'h7d;
            sbox[8'h14] = 8'hfa;
            sbox[8'h15] = 8'h59;
            sbox[8'h16] = 8'h47;
            sbox[8'h17] = 8'hf0;
            sbox[8'h18] = 8'had;
            sbox[8'h19] = 8'hd4;
            sbox[8'h1a] = 8'ha2;
            sbox[8'h1b] = 8'haf;
            sbox[8'h1c] = 8'h9c;
            sbox[8'h1d] = 8'ha4;
            sbox[8'h1e] = 8'h72;
            sbox[8'h1f] = 8'hc0;
            sbox[8'h20] = 8'hb7;
            sbox[8'h21] = 8'hfd;
            sbox[8'h22] = 8'h93;
            sbox[8'h23] = 8'h26;
            sbox[8'h24] = 8'h36;
            sbox[8'h25] = 8'h3f;
            sbox[8'h26] = 8'hf7;
            sbox[8'h27] = 8'hcc;
            sbox[8'h28] = 8'h34;
            sbox[8'h29] = 8'ha5;
            sbox[8'h2a] = 8'he5;
            sbox[8'h2b] = 8'hf1;
            sbox[8'h2c] = 8'h71;
            sbox[8'h2d] = 8'hd8;
            sbox[8'h2e] = 8'h31;
            sbox[8'h2f] = 8'h15;
            sbox[8'h30] = 8'h04;
            sbox[8'h31] = 8'hc7;
            sbox[8'h32] = 8'h23;
            sbox[8'h33] = 8'hc3;
            sbox[8'h34] = 8'h18;
            sbox[8'h35] = 8'h96;
            sbox[8'h36] = 8'h05;
            sbox[8'h37] = 8'h9a;
            sbox[8'h38] = 8'h07;
            sbox[8'h39] = 8'h12;
            sbox[8'h3a] = 8'h80;
            sbox[8'h3b] = 8'he2;
            sbox[8'h3c] = 8'heb;
            sbox[8'h3d] = 8'h27;
            sbox[8'h3e] = 8'hb2;
            sbox[8'h3f] = 8'h75;
            sbox[8'h40] = 8'h09;
            sbox[8'h41] = 8'h83;
            sbox[8'h42] = 8'h2c;
            sbox[8'h43] = 8'h1a;
            sbox[8'h44] = 8'h1b;
            sbox[8'h45] = 8'h6e;
            sbox[8'h46] = 8'h5a;
            sbox[8'h47] = 8'ha0;
            sbox[8'h48] = 8'h52;
            sbox[8'h49] = 8'h3b;
            sbox[8'h4a] = 8'hd6;
            sbox[8'h4b] = 8'hb3;
            sbox[8'h4c] = 8'h29;
            sbox[8'h4d] = 8'he3;
            sbox[8'h4e] = 8'h2f;
            sbox[8'h4f] = 8'h84;
            sbox[8'h50] = 8'h53;
            sbox[8'h51] = 8'hd1;
            sbox[8'h52] = 8'h00;
            sbox[8'h53] = 8'hed;
            sbox[8'h54] = 8'h20;
            sbox[8'h55] = 8'hfc;
            sbox[8'h56] = 8'hb1;
            sbox[8'h57] = 8'h5b;
            sbox[8'h58] = 8'h6a;
            sbox[8'h59] = 8'hcb;
            sbox[8'h5a] = 8'hbe;
            sbox[8'h5b] = 8'h39;
            sbox[8'h5c] = 8'h4a;
            sbox[8'h5d] = 8'h4c;
            sbox[8'h5e] = 8'h58;
            sbox[8'h5f] = 8'hcf;
            sbox[8'h60] = 8'hd0;
            sbox[8'h61] = 8'hef;
            sbox[8'h62] = 8'haa;
            sbox[8'h63] = 8'hfb;
            sbox[8'h64] = 8'h43;
            sbox[8'h65] = 8'h4d;
            sbox[8'h66] = 8'h33;
            sbox[8'h67] = 8'h85;
            sbox[8'h68] = 8'h45;
            sbox[8'h69] = 8'hf9;
            sbox[8'h6a] = 8'h02;
            sbox[8'h6b] = 8'h7f;
            sbox[8'h6c] = 8'h50;
            sbox[8'h6d] = 8'h3c;
            sbox[8'h6e] = 8'h9f;
            sbox[8'h6f] = 8'ha8;
            sbox[8'h70] = 8'h51;
            sbox[8'h71] = 8'ha3;
            sbox[8'h72] = 8'h40;
            sbox[8'h73] = 8'h8f;
            sbox[8'h74] = 8'h92;
            sbox[8'h75] = 8'h9d;
            sbox[8'h76] = 8'h38;
            sbox[8'h77] = 8'hf5;
            sbox[8'h78] = 8'hbc;
            sbox[8'h79] = 8'hb6;
            sbox[8'h7a] = 8'hda;
            sbox[8'h7b] = 8'h21;
            sbox[8'h7c] = 8'h10;
            sbox[8'h7d] = 8'hff;
            sbox[8'h7e] = 8'hf3;
            sbox[8'h7f] = 8'hd2;
            sbox[8'h80] = 8'hcd;
            sbox[8'h81] = 8'h0c;
            sbox[8'h82] = 8'h13;
            sbox[8'h83] = 8'hec;
            sbox[8'h84] = 8'h5f;
            sbox[8'h85] = 8'h97;
            sbox[8'h86] = 8'h44;
            sbox[8'h87] = 8'h17;
            sbox[8'h88] = 8'hc4;
            sbox[8'h89] = 8'ha7;
            sbox[8'h8a] = 8'h7e;
            sbox[8'h8b] = 8'h3d;
            sbox[8'h8c] = 8'h64;
            sbox[8'h8d] = 8'h5d;
            sbox[8'h8e] = 8'h19;
            sbox[8'h8f] = 8'h73;
            sbox[8'h90] = 8'h60;
            sbox[8'h91] = 8'h81;
            sbox[8'h92] = 8'h4f;
            sbox[8'h93] = 8'hdc;
            sbox[8'h94] = 8'h22;
            sbox[8'h95] = 8'h2a;
            sbox[8'h96] = 8'h90;
            sbox[8'h97] = 8'h88;
            sbox[8'h98] = 8'h46;
            sbox[8'h99] = 8'hee;
            sbox[8'h9a] = 8'hb8;
            sbox[8'h9b] = 8'h14;
            sbox[8'h9c] = 8'hde;
            sbox[8'h9d] = 8'h5e;
            sbox[8'h9e] = 8'h0b;
            sbox[8'h9f] = 8'hdb;
            sbox[8'ha0] = 8'he0;
            sbox[8'ha1] = 8'h32;
            sbox[8'ha2] = 8'h3a;
            sbox[8'ha3] = 8'h0a;
            sbox[8'ha4] = 8'h49;
            sbox[8'ha5] = 8'h06;
            sbox[8'ha6] = 8'h24;
            sbox[8'ha7] = 8'h5c;
            sbox[8'ha8] = 8'hc2;
            sbox[8'ha9] = 8'hd3;
            sbox[8'haa] = 8'hac;
            sbox[8'hab] = 8'h62;
            sbox[8'hac] = 8'h91;
            sbox[8'had] = 8'h95;
            sbox[8'hae] = 8'he4;
            sbox[8'haf] = 8'h79;
            sbox[8'hb0] = 8'he7;
            sbox[8'hb1] = 8'hc8;
            sbox[8'hb2] = 8'h37;
            sbox[8'hb3] = 8'h6d;
            sbox[8'hb4] = 8'h8d;
            sbox[8'hb5] = 8'hd5;
            sbox[8'hb6] = 8'h4e;
            sbox[8'hb7] = 8'ha9;
            sbox[8'hb8] = 8'h6c;
            sbox[8'hb9] = 8'h56;
            sbox[8'hba] = 8'hf4;
            sbox[8'hbb] = 8'hea;
            sbox[8'hbc] = 8'h65;
            sbox[8'hbd] = 8'h7a;
            sbox[8'hbe] = 8'hae;
            sbox[8'hbf] = 8'h08;
            sbox[8'hc0] = 8'hba;
            sbox[8'hc1] = 8'h78;
            sbox[8'hc2] = 8'h25;
            sbox[8'hc3] = 8'h2e;
            sbox[8'hc4] = 8'h1c;
            sbox[8'hc5] = 8'ha6;
            sbox[8'hc6] = 8'hb4;
            sbox[8'hc7] = 8'hc6;
            sbox[8'hc8] = 8'he8;
            sbox[8'hc9] = 8'hdd;
            sbox[8'hca] = 8'h74;
            sbox[8'hcb] = 8'h1f;
            sbox[8'hcc] = 8'h4b;
            sbox[8'hcd] = 8'hbd;
            sbox[8'hce] = 8'h8b;
            sbox[8'hcf] = 8'h8a;
            sbox[8'hd0] = 8'h70;
            sbox[8'hd1] = 8'h3e;
            sbox[8'hd2] = 8'hb5;
            sbox[8'hd3] = 8'h66;
            sbox[8'hd4] = 8'h48;
            sbox[8'hd5] = 8'h03;
            sbox[8'hd6] = 8'hf6;
            sbox[8'hd7] = 8'h0e;
            sbox[8'hd8] = 8'h61;
            sbox[8'hd9] = 8'h35;
            sbox[8'hda] = 8'h57;
            sbox[8'hdb] = 8'hb9;
            sbox[8'hdc] = 8'h86;
            sbox[8'hdd] = 8'hc1;
            sbox[8'hde] = 8'h1d;
            sbox[8'hdf] = 8'h9e;
            sbox[8'he0] = 8'he1;
            sbox[8'he1] = 8'hf8;
            sbox[8'he2] = 8'h98;
            sbox[8'he3] = 8'h11;
            sbox[8'he4] = 8'h69;
            sbox[8'he5] = 8'hd9;
            sbox[8'he6] = 8'h8e;
            sbox[8'he7] = 8'h94;
            sbox[8'he8] = 8'h9b;
            sbox[8'he9] = 8'h1e;
            sbox[8'hea] = 8'h87;
            sbox[8'heb] = 8'he9;
            sbox[8'hec] = 8'hce;
            sbox[8'hed] = 8'h55;
            sbox[8'hee] = 8'h28;
            sbox[8'hef] = 8'hdf;
            sbox[8'hf0] = 8'h8c;
            sbox[8'hf1] = 8'ha1;
            sbox[8'hf2] = 8'h89;
            sbox[8'hf3] = 8'h0d;
            sbox[8'hf4] = 8'hbf;
            sbox[8'hf5] = 8'he6;
            sbox[8'hf6] = 8'h42;
            sbox[8'hf7] = 8'h68;
            sbox[8'hf8] = 8'h41;
            sbox[8'hf9] = 8'h99;
            sbox[8'hfa] = 8'h2d;
            sbox[8'hfb] = 8'h0f;
            sbox[8'hfc] = 8'hb0;
            sbox[8'hfd] = 8'h54;
            sbox[8'hfe] = 8'hbb;
            sbox[8'hff] = 8'h16;
            
            for(i=0;i<128;i=i+8)
            begin
                SubBytes[i+:8] = sbox[State[i+:08]];
            end
        end
    endfunction
    
    // Key Expansion
    function [1279:0] key_expansion(input [127:0] key);
        reg [127 : 0] sub_key;
        reg [127 : 0] prev_key;
        reg [31:0] temp [0:3];
        reg [7:0] j[1:10];
        reg [1279:0] final_key;
        integer i;
        
        begin
            j[1]=8'h01;
            j[2]=8'h02;
            j[3]=8'h04;
            j[4]=8'h08;
            j[5]=8'h10;
            j[6]=8'h20;
            j[7]=8'h40;
            j[8]=8'h80;
            j[9]=8'h1b;
            j[10]=8'h36;
            prev_key = key;
            
            for(i=1;i<=10;i=i+1)
            begin
                sub_key = SubBytes(prev_key);
                temp[0] = prev_key[127:96]^ Shift_Column(sub_key[31:0]) ^ {j[i],24'h0};
                temp[1] = prev_key[95:64] ^ temp[0];
                temp[2] = prev_key[63:32] ^ temp[1];
                temp[3] = prev_key[31:0] ^ temp[2];
                prev_key = {temp[0], temp[1], temp[2], temp[3]};
                final_key[1279-(i-1)*128-:128] = prev_key;
            end
            
            key_expansion = final_key;
        end
    endfunction 
        
    function [31:0] Shift_Column(input [31:0] column);
        begin
            Shift_Column = {column[23:16],column[15:8],column[7:0],column[31:24]};
        end
    endfunction

    // AES Decryption Rounds
    integer a;
    always @*
        begin : implement
            reg [127 : 0] temp;
            reg [1279 : 0] full_key_expansion; 
            full_key_expansion = key_expansion(key);
            temp = Add_Round_key(CipherText, full_key_expansion[127:0]);
            temp = Inv_ShiftRow(temp);
            temp = InvSubBytes(temp);
        
            for(a=9;a>0;a=a-1)
            begin
                temp = Add_Round_key(temp, full_key_expansion[1279-(a-1)*128-:128]);
                temp = inv_mixcolumns(temp);
                temp = Inv_ShiftRow(temp);
                temp = InvSubBytes(temp);
            end
            
            PlainText = Add_Round_key(temp,key);                      
        end 
endmodule
