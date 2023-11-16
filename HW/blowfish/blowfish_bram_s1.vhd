--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity blowfish_bram_s1 is
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
architecture blowfish_bram_s1 of blowfish_bram_s1 is
  type ram_type is array (0 to 255) of std_logic_vector(31 downto 0);
  signal RAM : ram_type := (
   x"4B7A70E9",x"B5B32944",x"DB75092E",x"C4192623",x"AD6EA6B0",x"49A7DF7D",x"9CEE60B8",x"8FEDB266",
   x"ECAA8C71",x"699A17FF",x"5664526C",x"C2B19EE1",x"193602A5",x"75094C29",x"A0591340",x"E4183A3E",
   x"3F54989A",x"5B429D65",x"6B8FE4D6",x"99F73FD6",x"A1D29C07",x"EFE830F5",x"4D2D38E6",x"F0255DC1",
   x"4CDD2086",x"8470EB26",x"6382E9C6",x"021ECC5E",x"09686B3F",x"3EBAEFC9",x"3C971814",x"6B6A70A1",
   x"687F3584",x"52A0E286",x"B79C5305",x"AA500737",x"3E07841C",x"7FDEAE5C",x"8E7D44EC",x"5716F2B8",
   x"B03ADA37",x"F0500C0D",x"F01C1F04",x"0200B3FF",x"AE0CF51A",x"3CB574B2",x"25837A58",x"DC0921BD",
   x"D19113F9",x"7CA92FF6",x"94324773",x"22F54701",x"3AE5E581",x"37C2DADC",x"C8B57634",x"9AF3DDA7",
   x"A9446146",x"0FD0030E",x"ECC8C73E",x"A4751E41",x"E238CD99",x"3BEA0E2F",x"3280BBA1",x"183EB331",
   x"4E548B38",x"4F6DB908",x"6F420D03",x"F60A04BF",x"2CB81290",x"24977C79",x"5679B072",x"BCAF89AF",
   x"DE9A771F",x"D9930810",x"B38BAE12",x"DCCF3F2E",x"5512721F",x"2E6B7124",x"501ADDE6",x"9F84CD87",
   x"7A584718",x"7408DA17",x"BC9F9ABC",x"E94B7D8C",x"EC7AEC3A",x"DB851DFA",x"63094366",x"C464C3D2",
   x"EF1C1847",x"3215D908",x"DD433B37",x"24C2BA16",x"12A14D43",x"2A65C451",x"50940002",x"133AE4DD",
   x"71DFF89E",x"10314E55",x"81AC77D6",x"5F11199B",x"043556F1",x"D7A3C76B",x"3C11183B",x"5924A509",
   x"F28FE6ED",x"97F1FBFA",x"9EBABF2C",x"1E153C6E",x"86E34570",x"EAE96FB1",x"860E5E0A",x"5A3E2AB3",
   x"771FE71C",x"4E3D06FA",x"2965DCB9",x"99E71D0F",x"803E89D6",x"5266C825",x"2E4CC978",x"9C10B36A",
   x"C6150EBA",x"94E2EA78",x"A5FC3C53",x"1E0A2DF4",x"F2F74EA7",x"361D2B3D",x"1939260F",x"19C27960",
   x"5223A708",x"F71312B6",x"EBADFE6E",x"EAC31F66",x"E3BC4595",x"A67BC883",x"B17F37D1",x"018CFF28",
   x"C332DDEF",x"BE6C5AA5",x"65582185",x"68AB9802",x"EECEA50F",x"DB2F953B",x"2AEF7DAD",x"5B6E2F84",
   x"1521B628",x"29076170",x"ECDD4775",x"619F1510",x"13CCA830",x"EB61BD96",x"0334FE1E",x"AA0363CF",
   x"B5735C90",x"4C70A239",x"D59E9E0B",x"CBAADE14",x"EECC86BC",x"60622CA7",x"9CAB5CAB",x"B2F3846E",
   x"648B1EAF",x"19BDF0CA",x"A02369B9",x"655ABB50",x"40685A32",x"3C2AB4B3",x"319EE9D5",x"C021B8F7",
   x"9B540B19",x"875FA099",x"95F7997E",x"623D7DA8",x"F837889A",x"97E32D77",x"11ED935F",x"16681281",
   x"0E358829",x"C7E61FD6",x"96DEDFA1",x"7858BA99",x"57F584A5",x"1B227263",x"9B83C3FF",x"1AC24696",
   x"CDB30AEB",x"532E3054",x"8FD948E4",x"6DBC3128",x"58EBF2EF",x"34C6FFEA",x"FE28ED61",x"EE7C3C73",
   x"5D4A14D9",x"E864B7E3",x"42105D14",x"203E13E0",x"45EEE2B6",x"A3AAABEA",x"DB6C4F15",x"FACB4FD0",
   x"C742F442",x"EF6ABBB5",x"654F3B1D",x"41CD2105",x"D81E799E",x"86854DC7",x"E44B476A",x"3D816250",
   x"CF62A1F2",x"5B8D2646",x"FC8883A0",x"C1C7B6A3",x"7F1524C3",x"69CB7492",x"47848A0B",x"5692B285",
   x"095BBF00",x"AD19489D",x"1462B174",x"23820E00",x"58428D2A",x"0C55F5EA",x"1DADF43E",x"233F7061",
   x"3372F092",x"8D937E41",x"D65FECF1",x"6C223BDB",x"7CDE3759",x"CBEE7460",x"4085F2A7",x"CE77326E",
   x"A6078084",x"19F8509E",x"E8EFD855",x"61D99735",x"A969A7AA",x"C50C06C2",x"5A04ABFC",x"800BCADC",
   x"9E447A2E",x"C3453484",x"FDD56705",x"0E1E9EC9",x"DB73DBD3",x"105588CD",x"675FDA79",x"E3674340",
   x"C5C43465",x"713E38D8",x"3D28F89E",x"F16DFF20",x"153E21E7",x"8FB03D4A",x"E6E39F2B",x"DB83ADF7");

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
