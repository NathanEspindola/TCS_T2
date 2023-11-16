--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity blowfish_bram_s0 is
  port (
    clk     : in  std_logic;
    we      : in  std_logic;
    addr    : in  std_logic_vector(7 downto 0);
    data_i  : in  std_logic_vector(31 downto 0);
    data_o  : out std_logic_vector(31 downto 0)
  );
end entity;

--------------------------------------
-- Architecture
--------------------------------------
architecture blowfish_bram_s0 of blowfish_bram_s0 is
  type ram_type is array (0 to 255) of std_logic_vector(31 downto 0);
  signal RAM : ram_type := (
   x"D1310BA6",x"98DFB5AC",x"2FFD72DB",x"D01ADFB7",x"B8E1AFED",x"6A267E96",x"BA7C9045",x"F12C7F99",
   x"24A19947",x"B3916CF7",x"0801F2E2",x"858EFC16",x"636920D8",x"71574E69",x"A458FEA3",x"F4933D7E",
   x"0D95748F",x"728EB658",x"718BCD58",x"82154AEE",x"7B54A41D",x"C25A59B5",x"9C30D539",x"2AF26013",
   x"C5D1B023",x"286085F0",x"CA417918",x"B8DB38EF",x"8E79DCB0",x"603A180E",x"6C9E0E8B",x"B01E8A3E",
   x"D71577C1",x"BD314B27",x"78AF2FDA",x"55605C60",x"E65525F3",x"AA55AB94",x"57489862",x"63E81440",
   x"55CA396A",x"2AAB10B6",x"B4CC5C34",x"1141E8CE",x"A15486AF",x"7C72E993",x"B3EE1411",x"636FBC2A",
   x"2BA9C55D",x"741831F6",x"CE5C3E16",x"9B87931E",x"AFD6BA33",x"6C24CF5C",x"7A325381",x"28958677",
   x"3B8F4898",x"6B4BB9AF",x"C4BFE81B",x"66282193",x"61D809CC",x"FB21A991",x"487CAC60",x"5DEC8032",
   x"EF845D5D",x"E98575B1",x"DC262302",x"EB651B88",x"23893E81",x"D396ACC5",x"0F6D6FF3",x"83F44239",
   x"2E0B4482",x"A4842004",x"69C8F04A",x"9E1F9B5E",x"21C66842",x"F6E96C9A",x"670C9C61",x"ABD388F0",
   x"6A51A0D2",x"D8542F68",x"960FA728",x"AB5133A3",x"6EEF0B6C",x"137A3BE4",x"BA3BF050",x"7EFB2A98",
   x"A1F1651D",x"39AF0176",x"66CA593E",x"82430E88",x"8CEE8619",x"456F9FB4",x"7D84A5C3",x"3B8B5EBE",
   x"E06F75D8",x"85C12073",x"401A449F",x"56C16AA6",x"4ED3AA62",x"363F7706",x"1BFEDF72",x"429B023D",
   x"37D0D724",x"D00A1248",x"DB0FEAD3",x"49F1C09B",x"075372C9",x"80991B7B",x"25D479D8",x"F6E8DEF7",
   x"E3FE501A",x"B6794C3B",x"976CE0BD",x"04C006BA",x"C1A94FB6",x"409F60C4",x"5E5C9EC2",x"196A2463",
   x"68FB6FAF",x"3E6C53B5",x"1339B2EB",x"3B52EC6F",x"6DFC511F",x"9B30952C",x"CC814544",x"AF5EBD09",
   x"BEE3D004",x"DE334AFD",x"660F2807",x"192E4BB3",x"C0CBA857",x"45C8740F",x"D20B5F39",x"B9D3FBDB",
   x"5579C0BD",x"1A60320A",x"D6A100C6",x"402C7279",x"679F25FE",x"FB1FA3CC",x"8EA5E9F8",x"DB3222F8",
   x"3C7516DF",x"FD616B15",x"2F501EC8",x"AD0552AB",x"323DB5FA",x"FD238760",x"53317B48",x"3E00DF82",
   x"9E5C57BB",x"CA6F8CA0",x"1A87562E",x"DF1769DB",x"D542A8F6",x"287EFFC3",x"AC6732C6",x"8C4F5573",
   x"695B27B0",x"BBCA58C8",x"E1FFA35D",x"B8F011A0",x"10FA3D98",x"FD2183B8",x"4AFCB56C",x"2DD1D35B",
   x"9A53E479",x"B6F84565",x"D28E49BC",x"4BFB9790",x"E1DDF2DA",x"A4CB7E33",x"62FB1341",x"CEE4C6E8",
   x"EF20CADA",x"36774C01",x"D07E9EFE",x"2BF11FB4",x"95DBDA4D",x"AE909198",x"EAAD8E71",x"6B93D5A0",
   x"D08ED1D0",x"AFC725E0",x"8E3C5B2F",x"8E7594B7",x"8FF6E2FB",x"F2122B64",x"8888B812",x"900DF01C",
   x"4FAD5EA0",x"688FC31C",x"D1CFF191",x"B3A8C1AD",x"2F2F2218",x"BE0E1777",x"EA752DFE",x"8B021FA1",
   x"E5A0CC0F",x"B56F74E8",x"18ACF3D6",x"CE89E299",x"B4A84FE0",x"FD13E0B7",x"7CC43B81",x"D2ADA8D9",
   x"165FA266",x"80957705",x"93CC7314",x"211A1477",x"E6AD2065",x"77B5FA86",x"C75442F5",x"FB9D35CF",
   x"EBCDAF0C",x"7B3E89A0",x"D6411BD3",x"AE1E7E49",x"00250E2D",x"2071B35E",x"226800BB",x"57B8E0AF",
   x"2464369B",x"F009B91E",x"5563911D",x"59DFA6AA",x"78C14389",x"D95A537F",x"207D5BA2",x"02E5B9C5",
   x"83260376",x"6295CFA9",x"11C81968",x"4E734A41",x"B3472DCA",x"7B14A94A",x"1B510052",x"9A532915",
   x"D60F573F",x"BC9BC6E4",x"2B60A476",x"81E67400",x"08BA6FB5",x"571BE91F",x"F296EC6B",x"2A0DD915",
   x"B6636521",x"E7B9F9B6",x"FF34052E",x"C5855664",x"53B02D5D",x"A99F8FA1",x"08BA4799",x"6E85076A");

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
