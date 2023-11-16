// FILE NAME : cmsdk_ahb_crypt.v
// STATUS    : This file is a cryptography packet with an AHB interface.
// AUTHORS   : Rafael Garibotti, Jack Sampford
// E-mail    : rafael.garibotti@pucrs.br, j.w.sampford-15@student.lboro.ac.uk
//------------------------------------------------------------------------------
// RELEASE HISTORY
// VERSION   DATE         DESCRIPTION
// 1.0       2020-03-25   Initial version of the cryptography device.
// 1.1       2020-04-04   Updated to correct data block size
// 1.2       2020-04-08   Added duplex XTEA implementation
// 1.3       2020-04-14   Replaced duplex XTEA with optimised version
//------------------------------------------------------------------------------

module cmsdk_ahb_crypt (
  //AHBLITE INTERFACE
  //Slave Select Signals
  input wire         hsel_i,
  //Global Signal
  input wire         hclk,
  input wire         hreset_n,
  //Address, Control & Write Data
  input wire         hready_i,
  input wire  [31:0] haddr_i,
  input wire         hwrite_i,
  input wire  [31:0] hwdata_i,
  //Transfer Response & Read Data
  output wire        hreadyout_o,
  output wire        hresp_o,
  output wire [31:0] hrdata_o
);

//------------------------------------------------------------------------------
// Parameters
//------------------------------------------------------------------------------
localparam CRYPT_START   = 12'h300;
localparam CRYPT_READY   = 12'h500;
localparam CRYPT_CONFIG  = 12'h700;
localparam CRYPT_KEY     = 12'h900;
localparam CRYPT_PLAN    = 12'hB00;
localparam CRYPT_CIPHER  = 12'hD00;

//------------------------------------------------------------------------------
// Internal signals
//------------------------------------------------------------------------------
wire        crypt_rd;
wire        crypt_wr;

reg  [31:0] hrdata;
reg   [2:0] cnt_k_rd;
reg   [2:0] cnt_p_rd;
reg   [2:0] cnt_c_rd;
reg   [2:0] cnt_k_wr;
reg   [2:0] cnt_p_wr;
reg   [2:0] cnt_c_wr;
reg         st_k_wr;
reg         st_p_wr;
reg         st_c_wr;
reg         st_cfg;

wire        crypt_rst_n;   // reset_n
reg         crypt_reset_n; // reset_n "register"
reg         crypt_str;     // start
reg         crypt_rdy;     // ready
reg   [4:0] crypt_fsm;     // FSM
reg   [3:0] crypt_algo;    // algorithm
reg   [1:0] crypt_key;     // key
reg         crypt_plan;    // plan
reg         crypt_e_d;     // encoder (1) or decoder (0)

reg  [31:0] mem_key[7:0];    // Memory: Key
reg  [31:0] mem_plan[3:0];   // Memory: Plantext
reg  [31:0] mem_cipher[3:0]; // Memory: Ciphertext

//AES INTERFACE
wire [31:0] data_word_in;
wire        data_valid;
wire [31:0] ciphertext_word_in;
wire        ciphertext_valid;
wire  [1:0] key_length;
wire [31:0] key_word_in;
wire        key_valid;
wire        key_ready;
wire [31:0] ciphertext_word_out;
wire        ciphertext_ready;
wire [31:0] data_word_out;
wire        data_ready;

//BLOWFISH INTERFACE
wire        blowfish_busy_out;
wire [31:0] blowfish_data_word_in;
wire        blowfish_data_valid;
wire [31:0] blowfish_data_word_out;
wire        blowfish_data_ready;

//GOST INTERFACE
wire [31:0] gost_data_word_in;
wire        gost_data_valid;
wire [31:0] gost_data_word_out;
wire        gost_data_ready;

//NOEKEON INTERFACE
wire [31:0] noekeon_data_word_in;
wire        noekeon_data_valid;
wire [31:0] noekeon_data_word_out;
wire        noekeon_data_ready;

//SIMON INTERFACE
wire [31:0] simon_data_word_in;
wire        simon_data_valid;
wire [31:0] simon_data_word_out;
wire        simon_data_ready;

//XTEA INTERFACE
wire [31:0] xtea_data_word_in;
wire [31:0] xtea_ciphertext_word_in;
wire [31:0] xtea_data_word_out;
wire        xtea_data_ready;

//XTEA DUPLEX INTERFACE
wire [31:0] xtea_duplex_data_word_in;
wire        xtea_duplex_data_valid;
wire [31:0] xtea_duplex_ciphertext_word_in;
wire        xtea_duplex_ciphertext_valid;
wire [31:0] xtea_duplex_ciphertext_word_out;
wire        xtea_duplex_ciphertext_ready;
wire [31:0] xtea_duplex_data_word_out;
wire        xtea_duplex_data_ready;

//------------------------------------------------------------------------------
// Assigns
//------------------------------------------------------------------------------
assign hreadyout_o  = 1'b1; // Data always available
assign hresp_o      = 1'b0; // No generate errors
assign hrdata_o     = hrdata;

assign crypt_rd     = (hsel_i && !hwrite_i) ? 1'b1 : 1'b0;
assign crypt_wr     = (hsel_i &&  hwrite_i) ? 1'b1 : 1'b0;

assign crypt_rst_n  = (hreset_n && crypt_reset_n) ? 1'b1 : 1'b0;

assign key_length   = crypt_key;

assign key_valid    = (!(crypt_algo == 4'd13) && crypt_fsm >= 5'd2 && crypt_fsm <= 5'd9) ? 1'b1 : 1'b0;

assign key_word_in  = (crypt_fsm == 5'd2) ? mem_key[0] :
                      (crypt_fsm == 5'd3) ? mem_key[1] :
                      (crypt_fsm == 5'd4) ? mem_key[2] :
                      (crypt_fsm == 5'd5) ? mem_key[3] :
                      (crypt_fsm == 5'd6) ? mem_key[4] :
                      (crypt_fsm == 5'd7) ? mem_key[5] :
                      (crypt_fsm == 5'd8) ? mem_key[6] :
                      (crypt_fsm == 5'd9) ? mem_key[7] : 32'd0;

assign data_valid   = (crypt_e_d && crypt_fsm >= 5'd11 && crypt_fsm <= 5'd14) ? 1'b1 : 1'b0;

assign data_word_in = (crypt_e_d && crypt_fsm == 5'd11) ? mem_plan[0] :
                      (crypt_e_d && crypt_fsm == 5'd12) ? mem_plan[1] :
                      (crypt_e_d && crypt_fsm == 5'd13) ? mem_plan[2] :
                      (crypt_e_d && crypt_fsm == 5'd14) ? mem_plan[3] : 32'd0;

assign blowfish_data_valid   = (crypt_algo == 4'd2 && crypt_fsm >= 5'd11 && crypt_fsm <= 5'd14) ? 1'b1 : 1'b0;

assign blowfish_data_word_in = (crypt_algo == 4'd2 && crypt_fsm == 5'd11) ? mem_plan[0] :
                               (crypt_algo == 4'd2 && crypt_fsm == 5'd12) ? mem_plan[1] :
                               (crypt_algo == 4'd2 && crypt_fsm == 5'd13) ? mem_plan[2] :
                               (crypt_algo == 4'd2 && crypt_fsm == 5'd14) ? mem_plan[3] : 32'd0;


assign gost_data_valid   = (crypt_algo == 4'd4 && crypt_fsm >= 5'd11 && crypt_fsm <= 5'd12) ? 1'b1 : 1'b0;

assign gost_data_word_in = (crypt_algo == 4'd4 && crypt_fsm == 5'd11) ? mem_plan[0] :
                           (crypt_algo == 4'd4 && crypt_fsm == 5'd12) ? mem_plan[1] : 32'd0;

assign noekeon_data_valid   = (crypt_algo == 4'd7 && crypt_fsm >= 5'd11 && crypt_fsm <= 5'd14) ? 1'b1 : 1'b0;

assign noekeon_data_word_in = (crypt_algo == 4'd7 && crypt_fsm == 5'd11) ? mem_plan[0] :
                              (crypt_algo == 4'd7 && crypt_fsm == 5'd12) ? mem_plan[1] :
                              (crypt_algo == 4'd7 && crypt_fsm == 5'd13) ? mem_plan[2] :
                              (crypt_algo == 4'd7 && crypt_fsm == 5'd14) ? mem_plan[3] : 32'd0;

assign simon_data_valid   = (crypt_algo == 4'd10 && crypt_fsm >= 5'd11 && crypt_fsm <= 5'd14) ? 1'b1 : 1'b0;

assign simon_data_word_in = (crypt_algo == 4'd10 && crypt_fsm == 5'd11) ? mem_plan[0] :
                            (crypt_algo == 4'd10 && crypt_fsm == 5'd12) ? mem_plan[1] :
                            (crypt_algo == 4'd10 && crypt_fsm == 5'd13) ? mem_plan[2] :
                            (crypt_algo == 4'd10 && crypt_fsm == 5'd14) ? mem_plan[3] : 32'd0;

assign ciphertext_valid   = (!crypt_e_d && crypt_fsm >= 5'd11 && crypt_fsm <= 5'd14) ? 1'b1 : 1'b0;

assign ciphertext_word_in = (!crypt_e_d && crypt_fsm == 5'd11) ? mem_plan[0] :
                            (!crypt_e_d && crypt_fsm == 5'd12) ? mem_plan[1] :
                            (!crypt_e_d && crypt_fsm == 5'd13) ? mem_plan[2] :
                            (!crypt_e_d && crypt_fsm == 5'd14) ? mem_plan[3] : 32'd0;

assign xtea_data_word_in = (crypt_algo == 4'd12 && crypt_fsm == 5'd2) ? mem_plan[0] :
                           (crypt_algo == 4'd12 && crypt_fsm == 5'd3) ? mem_plan[1] :
                           (crypt_algo == 4'd12 && crypt_fsm == 5'd4) ? mem_plan[2] :
                           (crypt_algo == 4'd12 && crypt_fsm == 5'd5) ? mem_plan[3] : 32'd0;

assign xtea_duplex_data_valid    = (crypt_algo == 4'd13 && crypt_e_d && crypt_fsm >= 5'd2 && crypt_fsm <= 5'd5) ? 1'b1 : 1'b0;

assign xtea_duplex_data_word_in  = (crypt_algo == 4'd13 && crypt_e_d && crypt_fsm == 5'd2) ? mem_plan[0] :
                                   (crypt_algo == 4'd13 && crypt_e_d && crypt_fsm == 5'd3) ? mem_plan[1] :
                                   (crypt_algo == 4'd13 && crypt_e_d && crypt_fsm == 5'd4) ? mem_plan[2] :
                                   (crypt_algo == 4'd13 && crypt_e_d && crypt_fsm == 5'd5) ? mem_plan[3] : 32'd0;

assign xtea_duplex_ciphertext_valid   = (crypt_algo == 4'd13 && !crypt_e_d && crypt_fsm >= 5'd2 && crypt_fsm <= 5'd5) ? 1'b1 : 1'b0;

assign xtea_duplex_ciphertext_word_in = (crypt_algo == 4'd13 && !crypt_e_d && crypt_fsm == 5'd2) ? mem_plan[0] :
                                        (crypt_algo == 4'd13 && !crypt_e_d && crypt_fsm == 5'd3) ? mem_plan[1] :
                                        (crypt_algo == 4'd13 && !crypt_e_d && crypt_fsm == 5'd4) ? mem_plan[2] :
                                        (crypt_algo == 4'd13 && !crypt_e_d && crypt_fsm == 5'd5) ? mem_plan[3] : 32'd0;

//-------------------------------------------
// Communication with AHBLite
//-------------------------------------------
always @(posedge hclk or negedge hreset_n)
begin
  if (!hreset_n) begin
    hrdata   <= 32'h0;
    cnt_k_rd <= 3'd0;
    cnt_p_rd <= 3'd0;
    cnt_c_rd <= 3'd0;
  end
  else begin
    //-------------------------------------------
    // Send data to AHBLite
    //-------------------------------------------
    if (crypt_rd) begin
      //CRYPT: READ MEM_KEY
      if (haddr_i[15:4] == CRYPT_KEY) begin
        hrdata     <= mem_key[cnt_k_rd];
        cnt_k_rd   <= cnt_k_rd + 3'd1;
      end
      //CRYPT: READ MEM_PLAN
      else if (haddr_i[15:4] == CRYPT_PLAN) begin
        hrdata     <= mem_plan[cnt_p_rd];
        cnt_p_rd   <= cnt_p_rd + 3'd1;
      end
      //CRYPT: READ MEM_CIPHER
      else if (haddr_i[15:4] == CRYPT_CIPHER) begin
        hrdata     <= mem_cipher[cnt_c_rd];
        cnt_c_rd   <= cnt_c_rd + 3'd1;
      end
      //CRYPT: READY
      else if (haddr_i[15:4] == CRYPT_READY) begin
        hrdata     <= {31'd0, crypt_rdy};
        if (crypt_rdy) begin
          cnt_k_rd <= 3'd0;
          cnt_p_rd <= 3'd0;
          cnt_c_rd <= 3'd0;
        end 
      end
      //CRYPT: CONFIG
      else if (haddr_i[15:4] == CRYPT_CONFIG) begin
        hrdata     <= {24'd0, crypt_algo, crypt_key, crypt_plan, crypt_e_d};
      end
    end
  end
end

//-------------------------------------------
// CRYPT: Internal Memory
//-------------------------------------------
integer i;
always @(posedge hclk or negedge hreset_n)
begin
  if (!hreset_n) begin
    crypt_reset_n <= 1'b1;
    crypt_rdy     <= 1'b0;
    crypt_str     <= 1'b0;
    crypt_algo    <= 4'd0;
    crypt_key     <= 2'd0;
    crypt_plan    <= 1'b0;
    crypt_e_d     <= 1'b1; // 0: decoder, 1: encoder
    crypt_fsm     <= 5'd0;
    st_cfg        <= 1'b0;
    st_k_wr       <= 1'b0;
    st_p_wr       <= 1'b0;
    st_c_wr       <= 1'b0;
    cnt_k_wr      <= 3'd0;
    cnt_p_wr      <= 3'd0;
    cnt_c_wr      <= 3'd0;
    for (i=0; i<8; i=i+1) mem_key[i]    <= 32'd0;
    for (i=0; i<4; i=i+1) mem_plan[i]   <= 32'd0;
    for (i=0; i<4; i=i+1) mem_cipher[i] <= 32'd0;
  end
  else begin
    //----------------------------------------------
    // Cryptography Process (FSM)
    // 0 : reset cryptography
    // 1 : start cryptography
    // 2-5 : send the key (128 bits) and data for XTEA
    // 6-7 : send the key (192 bits)
    // 8-9 : send the key (256 bits)
    // 10 : wait for expansion to complete
    // 11-12 : send the plantext (enc/dec - 64 bits)
    // 13-14 : send the plantext (enc/dec - 128 bits)
    // 15 : wait until encryption/decryption complete
    // 16-18 : receive the ciphertext (128 bits)
    // 19 : cryptography ready
    //----------------------------------------------
    if (crypt_str) begin
      case (crypt_fsm)
        5'd0 : begin
          crypt_reset_n <= 1'b0;
          crypt_fsm     <= crypt_fsm + 5'd1;
        end
        5'd1 : begin
          crypt_reset_n <= 1'b1;
          crypt_fsm     <= crypt_fsm + 5'd1;
        end
        5'd2, 5'd3, 5'd4 : begin
          crypt_fsm     <= crypt_fsm + 5'd1;
        end
        5'd5 : begin
          if (crypt_algo == 4'd12 || crypt_algo == 4'd13) begin //XTEA or XTEA_DUPLEX
            crypt_fsm   <= 5'd15;
          end
          else if (crypt_key == 2'd0) begin //128 bits
            crypt_fsm   <= 5'd10;
          end
          else begin //192 or 256 bits
            crypt_fsm   <= crypt_fsm + 5'd1;
          end
        end
        5'd6 : begin
          crypt_fsm     <= crypt_fsm + 5'd1;
        end
        5'd7 : begin
          if (crypt_key == 2'd1) begin //192 bits
            crypt_fsm   <= 5'd10;
          end
          else begin //256 bits
            crypt_fsm   <= crypt_fsm + 5'd1;
          end
        end
        5'd8, 5'd9 : begin
          crypt_fsm     <= crypt_fsm + 5'd1;
        end
        5'd10 : begin
          if ((crypt_algo != 4'd0) || key_ready) begin
            crypt_fsm   <= crypt_fsm + 5'd1;
          end
        end
        5'd11 : begin
          crypt_fsm     <= crypt_fsm + 5'd1;
        end
        5'd12 : begin
          if (crypt_plan == 1'b0) begin //64 bits
            crypt_fsm   <= 5'd15;
          end
          else begin //128 bits
            crypt_fsm   <= crypt_fsm + 5'd1;
          end
        end
        5'd13, 5'd14 : begin
          crypt_fsm     <= crypt_fsm + 5'd1;
        end
        5'd15 : begin
          if ((crypt_algo == 4'd0) && (ciphertext_ready || data_ready)) begin
            crypt_fsm <= crypt_fsm + 5'd1;
            //AES
            if (crypt_e_d) begin
              mem_cipher[0] <= ciphertext_word_out;
            end
            else begin
              mem_cipher[0] <= data_word_out;
            end
          end
          else if (crypt_algo == 4'd2 && blowfish_data_ready) begin
            crypt_fsm <= crypt_fsm + 5'd1;
            //BLOWFISH
            mem_cipher[0] <= blowfish_data_word_out;
          end
          else if (crypt_algo == 4'd4 && gost_data_ready) begin
            crypt_fsm <= crypt_fsm + 5'd1;
            //GOST
            mem_cipher[0] <= gost_data_word_out;
          end
          else if (crypt_algo == 4'd7 && noekeon_data_ready) begin
            crypt_fsm <= crypt_fsm + 5'd1;
            //NOEKEON
            mem_cipher[0] <= noekeon_data_word_out;
          end
          else if (crypt_algo == 4'd10 && simon_data_ready) begin
            crypt_fsm <= crypt_fsm + 5'd1;
            //SIMON
            mem_cipher[0] <= simon_data_word_out;
          end
          else if (crypt_algo == 4'd12 && xtea_data_ready) begin
            crypt_fsm <= crypt_fsm + 5'd1;
            //XTEA
            mem_cipher[0] <= xtea_data_word_out;
          end
          else if (crypt_algo == 4'd13 && (xtea_duplex_ciphertext_ready || xtea_duplex_data_ready)) begin
            crypt_fsm <= crypt_fsm + 5'd1;
            //XTEA duplex
            if (crypt_e_d) begin
              mem_cipher[0] <= xtea_duplex_ciphertext_word_out;
            end
            else begin
              mem_cipher[0] <= xtea_duplex_data_word_out;
            end
          end
        end
        5'd16 : begin
          if (crypt_algo == 4'd0 && ciphertext_ready) begin
            mem_cipher[1] <= ciphertext_word_out;
          end
          else if (crypt_algo == 4'd0 && data_ready) begin
            mem_cipher[1] <= data_word_out;
          end
          else if (crypt_algo == 4'd2 && blowfish_data_ready) begin
            mem_cipher[1] <= blowfish_data_word_out;
          end
          else if (crypt_algo == 4'd4 && gost_data_ready) begin
            mem_cipher[1] <= gost_data_word_out;
          end
          else if (crypt_algo == 4'd7 && noekeon_data_ready) begin
            mem_cipher[1] <= noekeon_data_word_out;
          end
          else if (crypt_algo == 4'd10 && simon_data_ready) begin
            mem_cipher[1] <= simon_data_word_out;
          end
          else if (crypt_algo == 4'd12 && xtea_data_ready) begin
            mem_cipher[1] <= xtea_data_word_out;
          end
          else if (crypt_algo == 4'd13 && xtea_duplex_ciphertext_ready) begin
            mem_cipher[1] <= xtea_duplex_ciphertext_word_out;
          end
          else if (crypt_algo == 4'd13 && xtea_duplex_data_ready) begin
            mem_cipher[1] <= xtea_duplex_data_word_out;
          end
          crypt_fsm       <= crypt_fsm + 5'd1;
        end
        5'd17 : begin
          if (crypt_algo == 4'd0 && ciphertext_ready) begin
            mem_cipher[2] <= ciphertext_word_out;
          end
          else if (crypt_algo == 4'd0 && data_ready) begin
            mem_cipher[2] <= data_word_out;
          end
          else if (crypt_algo == 4'd2 && blowfish_data_ready) begin
            mem_cipher[2] <= blowfish_data_word_out;
          end
          else if (crypt_algo == 4'd7 && noekeon_data_ready) begin
            mem_cipher[2] <= noekeon_data_word_out;
          end
          else if (crypt_algo == 4'd10 && simon_data_ready) begin
            mem_cipher[2] <= simon_data_word_out;
          end
          else if (crypt_algo == 4'd12 && xtea_data_ready) begin
            mem_cipher[2] <= xtea_data_word_out;
          end
          else if (crypt_algo == 4'd13 && xtea_duplex_ciphertext_ready) begin
            mem_cipher[2] <= xtea_duplex_ciphertext_word_out;
          end
          else if (crypt_algo == 4'd13 && xtea_duplex_data_ready) begin
            mem_cipher[2] <= xtea_duplex_data_word_out;
          end
          crypt_fsm       <= crypt_fsm + 5'd1;
        end
        5'd18 : begin
          if (crypt_algo == 4'd0 && ciphertext_ready) begin
            mem_cipher[3] <= ciphertext_word_out;
          end
          else if (crypt_algo == 4'd0 && data_ready) begin
            mem_cipher[3] <= data_word_out;
          end
          else if (crypt_algo == 4'd2 && blowfish_data_ready) begin
            mem_cipher[3] <= blowfish_data_word_out;
          end
          else if (crypt_algo == 4'd7 && noekeon_data_ready) begin
            mem_cipher[3] <= noekeon_data_word_out;
          end
          else if (crypt_algo == 4'd10 && simon_data_ready) begin
            mem_cipher[3] <= simon_data_word_out;
          end
          else if (crypt_algo == 4'd12 && xtea_data_ready) begin
            mem_cipher[3] <= xtea_data_word_out;
          end
          else if (crypt_algo == 4'd13 && xtea_duplex_ciphertext_ready) begin
            mem_cipher[3] <= xtea_duplex_ciphertext_word_out;
          end
          else if (crypt_algo == 4'd13 && xtea_duplex_data_ready) begin
            mem_cipher[3] <= xtea_duplex_data_word_out;
          end
          crypt_fsm       <= crypt_fsm + 5'd1;
        end
        default : begin
          crypt_rdy     <= 1'b1;
          crypt_fsm     <= 5'd0;
          crypt_str     <= 1'b0;
        end
      endcase
    end
    //-------------------------------------------
    // Receive data from AHBLite
    //-------------------------------------------
    else if (crypt_wr) begin
      //CRYPT: WRITE MEM_KEY
      if (haddr_i[15:4] == CRYPT_KEY) begin
        st_k_wr <= 1'b1;
      end
      //CRYPT: WRITE MEM_PLAN
      else if (haddr_i[15:4] == CRYPT_PLAN) begin
        st_p_wr <= 1'b1;
      end
      //CRYPT: WRITE MEM_CIPHER
      else if (haddr_i[15:4] == CRYPT_CIPHER) begin
        st_c_wr <= 1'b1;
      end
      //CRYPT: WRITE CONFIG
      else if (haddr_i[15:4] == CRYPT_CONFIG) begin
        st_cfg  <= 1'b1;
      end
      //CRYPT: START
      else if (haddr_i[15:4] == CRYPT_START) begin
        crypt_str <= 1'b1;
        crypt_rdy <= 1'b0;
        cnt_k_wr  <= 3'd0;
        cnt_p_wr  <= 3'd0;
        cnt_c_wr  <= 3'd0;
      end
    end
    else if (st_k_wr) begin
      st_k_wr   <= 1'b0;
      mem_key[cnt_k_wr] <= hwdata_i;
      cnt_k_wr  <= cnt_k_wr + 3'd1;
    end
    else if (st_p_wr) begin
      st_p_wr   <= 1'b0;
      mem_plan[cnt_p_wr] <= hwdata_i;
      cnt_p_wr  <= cnt_p_wr + 3'd1;
    end
    else if (st_c_wr) begin
      st_c_wr   <= 1'b0;
      mem_cipher[cnt_c_wr] <= hwdata_i;
      cnt_c_wr  <= cnt_c_wr + 3'd1;
    end
    else if (st_cfg) begin
      st_cfg     <= 1'b0;
      crypt_algo <= hwdata_i[7:4];
      crypt_key  <= hwdata_i[3:2];
      crypt_plan <= hwdata_i[1];
      crypt_e_d  <= hwdata_i[0];
    end
  end
end

// ------------------------------------------------------------
//  AES
// ------------------------------------------------------------
aes_top u_aes_top (
  .clk                 (hclk),
  .reset_n             (crypt_rst_n),
  //AES INTERFACE
  .data_word_in        (data_word_in),
  .data_valid          (data_valid),
  .ciphertext_word_in  (ciphertext_word_in),
  .ciphertext_valid    (ciphertext_valid),
  .key_length          (key_length),
  .key_word_in         (key_word_in),
  .key_valid           (key_valid),
  .key_ready           (key_ready),
  .ciphertext_word_out (ciphertext_word_out),
  .ciphertext_ready    (ciphertext_ready),
  .data_word_out       (data_word_out),
  .data_ready          (data_ready)
);

// ------------------------------------------------------------
//  BLOWFISH
// ------------------------------------------------------------
blowfish_top u_blowfish_top (
  .clk                 (hclk),
  .reset_n             (crypt_rst_n),
  //BLOWFISH INTERFACE
  .encryption          (crypt_e_d),
  .key_length          (key_length),
  .key_valid           (key_valid),
  .key_word_in         (key_word_in),
  .data_valid          (blowfish_data_valid),
  .data_word_in        (blowfish_data_word_in),
  .crypt_busy_out      (blowfish_busy_out),
  .ciphertext_word_out (blowfish_data_word_out),
  .ciphertext_ready    (blowfish_data_ready)
);

// ------------------------------------------------------------
//  GOST
// ------------------------------------------------------------
gost_top u_gost_top (
  .clk                 (hclk),
  .reset_n             (crypt_rst_n),
  //GOST INTERFACE
  .encryption          (crypt_e_d),
  .key_valid           (key_valid),
  .key_word_in         (key_word_in),
  .data_valid          (gost_data_valid),
  .data_word_in        (gost_data_word_in),
  .data_word_out       (gost_data_word_out),
  .data_ready          (gost_data_ready)
);

// ------------------------------------------------------------
//  NOEKEON
// ------------------------------------------------------------
noekeon_top u_noekeon_top (
  .clk                 (hclk),
  .reset_n             (crypt_rst_n),
  //NOEKEON INTERFACE
  .encryption          (crypt_e_d),
  .key_valid           (key_valid),
  .key_word_in         (key_word_in),
  .data_valid          (noekeon_data_valid),
  .data_word_in        (noekeon_data_word_in),
  .data_word_out       (noekeon_data_word_out),
  .data_ready          (noekeon_data_ready)
);

// ------------------------------------------------------------
//  SIMON
// ------------------------------------------------------------
simon_top u_simon_top (
  .clk                 (hclk),
  .reset_n             (crypt_rst_n),
  //SMON INTERFACE
  .encryption          (crypt_e_d),
  .key_length          (key_length),
  .key_valid           (key_valid),
  .key_word_in         (key_word_in),
  .data_valid          (simon_data_valid),
  .data_word_in        (simon_data_word_in),
  .data_word_out       (simon_data_word_out),
  .data_ready          (simon_data_ready)
);

// ------------------------------------------------------------
//  XTEA
// ------------------------------------------------------------
xtea_top u_xtea_top (
  .clk                 (hclk),
  .reset_n             (crypt_rst_n),
  //XTEA INTERFACE
  .encryption          (crypt_e_d),
  .key_data_valid      (key_valid),
  .key_word_in         (key_word_in),
  .data_word_in        (xtea_data_word_in),
  .data_word_out       (xtea_data_word_out),
  .data_ready          (xtea_data_ready)
);

// ------------------------------------------------------------
//  XTEA duplex
// ------------------------------------------------------------
xtea_top_duplex u_xtea_top_duplex (
  .clk                 (hclk),
  .reset_n             (crypt_rst_n),
  //XTEA INTERFACE
  .data_word_in        (xtea_duplex_data_word_in),
  .data_valid          (xtea_duplex_data_valid),
  .ciphertext_word_in  (xtea_duplex_ciphertext_word_in),
  .ciphertext_valid    (xtea_duplex_ciphertext_valid),
  .key_word_in         (key_word_in),
  .ciphertext_word_out (xtea_duplex_ciphertext_word_out),
  .ciphertext_ready    (xtea_duplex_ciphertext_ready),
  .data_word_out       (xtea_duplex_data_word_out),
  .data_ready          (xtea_duplex_data_ready)
);

endmodule