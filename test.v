`timescale 1ns / 1ps

module TB;
	reg [127:0] Test_State;
	reg [127:0] Test_Key;
	wire [127:0] Test_Result;
	
	AES_Decrypter a(Test_State,Test_Key,Test_Result);
	
	initial
	begin
	   Test_State = 128'hff0b844a0853bf7c6934ab4364148fb9;
	   Test_Key = 128'h0f1571c947d9e8590cb7add6af7f6798;
	end
endmodule
