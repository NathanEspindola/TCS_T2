--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity blowfish_bram_s3 is
  port (
    clk    : in  std_logic;
    we     : in  std_logic;
    addr   : in  std_logic_vector(7 downto 0);
    data_i : in  std_logic_vector(31 downto 0);
    data_o : out std_logic_vector(31 downto 0)
  );
end entity;

--------------------------------------
-- Architecture
--------------------------------------
architecture blowfish_bram_s3 of blowfish_bram_s3 is
  type ram_type is array (0 to 255) of std_logic_vector(31 downto 0);
  signal RAM : ram_type := (
   x"3A39CE37",x"D3FAF5CF",x"ABC27737",x"5AC52D1B",x"5CB0679E",x"4FA33742",x"D3822740",x"99BC9BBE",
   x"D5118E9D",x"BF0F7315",x"D62D1C7E",x"C700C47B",x"B78C1B6B",x"21A19045",x"B26EB1BE",x"6A366EB4",
   x"5748AB2F",x"BC946E79",x"C6A376D2",x"6549C2C8",x"530FF8EE",x"468DDE7D",x"D5730A1D",x"4CD04DC6",
   x"2939BBDB",x"A9BA4650",x"AC9526E8",x"BE5EE304",x"A1FAD5F0",x"6A2D519A",x"63EF8CE2",x"9A86EE22",
   x"C089C2B8",x"43242EF6",x"A51E03AA",x"9CF2D0A4",x"83C061BA",x"9BE96A4D",x"8FE51550",x"BA645BD6",
   x"2826A2F9",x"A73A3AE1",x"4BA99586",x"EF5562E9",x"C72FEFD3",x"F752F7DA",x"3F046F69",x"77FA0A59",
   x"80E4A915",x"87B08601",x"9B09E6AD",x"3B3EE593",x"E990FD5A",x"9E34D797",x"2CF0B7D9",x"022B8B51",
   x"96D5AC3A",x"017DA67D",x"D1CF3ED6",x"7C7D2D28",x"1F9F25CF",x"ADF2B89B",x"5AD6B472",x"5A88F54C",
   x"E029AC71",x"E019A5E6",x"47B0ACFD",x"ED93FA9B",x"E8D3C48D",x"283B57CC",x"F8D56629",x"79132E28",
   x"785F0191",x"ED756055",x"F7960E44",x"E3D35E8C",x"15056DD4",x"88F46DBA",x"03A16125",x"0564F0BD",
   x"C3EB9E15",x"3C9057A2",x"97271AEC",x"A93A072A",x"1B3F6D9B",x"1E6321F5",x"F59C66FB",x"26DCF319",
   x"7533D928",x"B155FDF5",x"03563482",x"8ABA3CBB",x"28517711",x"C20AD9F8",x"ABCC5167",x"CCAD925F",
   x"4DE81751",x"3830DC8E",x"379D5862",x"9320F991",x"EA7A90C2",x"FB3E7BCE",x"5121CE64",x"774FBE32",
   x"A8B6E37E",x"C3293D46",x"48DE5369",x"6413E680",x"A2AE0810",x"DD6DB224",x"69852DFD",x"09072166",
   x"B39A460A",x"6445C0DD",x"586CDECF",x"1C20C8AE",x"5BBEF7DD",x"1B588D40",x"CCD2017F",x"6BB4E3BB",
   x"DDA26A7E",x"3A59FF45",x"3E350A44",x"BCB4CDD5",x"72EACEA8",x"FA6484BB",x"8D6612AE",x"BF3C6F47",
   x"D29BE463",x"542F5D9E",x"AEC2771B",x"F64E6370",x"740E0D8D",x"E75B1357",x"F8721671",x"AF537D5D",
   x"4040CB08",x"4EB4E2CC",x"34D2466A",x"0115AF84",x"E1B00428",x"95983A1D",x"06B89FB4",x"CE6EA048",
   x"6F3F3B82",x"3520AB82",x"011A1D4B",x"277227F8",x"611560B1",x"E7933FDC",x"BB3A792B",x"344525BD",
   x"A08839E1",x"51CE794B",x"2F32C9B7",x"A01FBAC9",x"E01CC87E",x"BCC7D1F6",x"CF0111C3",x"A1E8AAC7",
   x"1A908749",x"D44FBD9A",x"D0DADECB",x"D50ADA38",x"0339C32A",x"C6913667",x"8DF9317C",x"E0B12B4F",
   x"F79E59B7",x"43F5BB3A",x"F2D519FF",x"27D9459C",x"BF97222C",x"15E6FC2A",x"0F91FC71",x"9B941525",
   x"FAE59361",x"CEB69CEB",x"C2A86459",x"12BAA8D1",x"B6C1075E",x"E3056A0C",x"10D25065",x"CB03A442",
   x"E0EC6E0E",x"1698DB3B",x"4C98A0BE",x"3278E964",x"9F1F9532",x"E0D392DF",x"D3A0342B",x"8971F21E",
   x"1B0A7441",x"4BA3348C",x"C5BE7120",x"C37632D8",x"DF359F8D",x"9B992F2E",x"E60B6F47",x"0FE3F11D",
   x"E54CDA54",x"1EDAD891",x"CE6279CF",x"CD3E7E6F",x"1618B166",x"FD2C1D05",x"848FD2C5",x"F6FB2299",
   x"F523F357",x"A6327623",x"93A83531",x"56CCCD02",x"ACF08162",x"5A75EBB5",x"6E163697",x"88D273CC",
   x"DE966292",x"81B949D0",x"4C50901B",x"71C65614",x"E6C6C7BD",x"327A140A",x"45E1D006",x"C3F27B9A",
   x"C9AA53FD",x"62A80F00",x"BB25BFE2",x"35BDD2F6",x"71126905",x"B2040222",x"B6CBCF7C",x"CD769C2B",
   x"53113EC0",x"1640E3D3",x"38ABBD60",x"2547ADF0",x"BA38209C",x"F746CE76",x"77AFA1C5",x"20756060",
   x"85CBFE4E",x"8AE88DD8",x"7AAAF9B0",x"4CF9AA7E",x"1948C25C",x"02FB8A8C",x"01C36AE4",x"D6EBE1F9",
   x"90D4F869",x"A65CDEA0",x"3F09252D",x"C208E69F",x"B74E6132",x"CE77E25B",x"578FDFE3",x"3AC372E6");

begin

  process (clk)
  begin
    if falling_edge(clk) then
      if (we = '1') then
        RAM(conv_integer(addr)) <= data_i;
      end if;
    end if;
  end process;

  data_o <= RAM(conv_integer(addr));

end architecture;
