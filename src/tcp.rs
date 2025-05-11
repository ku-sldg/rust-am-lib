// tcp.rs (tcp utilities)
use tokio::net::TcpSocket;
use tokio::net::TcpStream;
use std::net::SocketAddr;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

pub async fn connect_tcp_stream (server_uuid_string:String, client_uuid_string:String) -> std::io::Result<tokio::net::TcpStream> {

    let socket: TcpSocket = TcpSocket::new_v4()?;

    let server_addr: SocketAddr = server_uuid_string.parse().unwrap();

    let maybe_client_addr_string: Option<String> =
        if client_uuid_string == "".to_string()
        { None }
        else 
        {
            Some (client_uuid_string)
        };

    match maybe_client_addr_string {
        Some (client_addr_string) => {

            let client_addr: SocketAddr = client_addr_string.parse().unwrap();
            socket.set_reuseaddr(true)?;
            socket.bind(client_addr)?;

            eprintln!("\n{}{}{}{}", "Trying to connect to server at address:  ", server_addr, " from FIXED client address: ", client_addr);
            let stream = socket.connect(server_addr).await?;
            Ok(stream)

        }
        None => {
            eprintln!("\n{}{}{}", "Trying to connect to server at address:  ", server_addr, " from EPHEMERAL (OS-chosen) client address");
            let stream = socket.connect(server_addr).await?;
            Ok(stream)

        }
    }
}

#[allow(non_snake_case)]
pub async fn am_sendRec_string (s:String, mut stream:TcpStream) -> std::io::Result<String> {
    let sbytes = s.as_bytes();
    let sbytes_len: u32 = sbytes.len().try_into().unwrap();

    // Write a buffer of bytes representing the (u32) size of the string to be sent
    let mut wtr = vec![];
    AsyncWriteExt::write_u32(& mut wtr,sbytes_len).await?;//.unwrap();
    stream.write_all(&wtr).await?;

    // Write the string as bytes
    stream.try_write(s.as_bytes())?;

    // This is a hack to read 4 bytes from the stream (peeling off the response buffer size)
    // TODO:  We should probably use/decode this value in the future if we keep this approach
    let mut x:[u8; 4] = [0u8;4];
    stream.read_exact(&mut x).await?;
    //stream.try_read(&mut x)?;

    // Read in response string from stream
    let mut str_in : String = String::new();
    stream.read_to_string(&mut str_in).await?;

    // Clone and return response string
    let str_out : String = str_in.clone();
    Ok (str_out)
}