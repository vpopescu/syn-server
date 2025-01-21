/**
 * Network related functionality
 *
 */
use std::{
    //io::{Read, Write},
    //net::{TcpListener, TcpStream, UdpSocket},
    sync::Arc,    
};

use crate::{stun::{self, processor::MessageProcessor}, Context};
use slog::{debug, error};
use tokio::{io::AsyncWriteExt, task::JoinHandle};
use tokio::time::{timeout, Duration}; 
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/**
 * Network server that handles TCP and UDP connections.
 */
pub(crate) struct NetworkServer<T: MessageProcessor> {
    context: Arc<Context>,
    processor: T,
}

impl<T: MessageProcessor> NetworkServer<T>
where
    T: Clone + Send + 'static,
{
    /**
     * Initialize a new network server. The context contains global logger
     * and configuration settings, and the message processor is used to
     * do protocol-specific message processing (in this case STUN)
     */
    pub fn new(context: &Arc<Context>, message_processor: T) -> Self {
        Self {
            context: Arc::clone(context),
            processor: message_processor,
        }
    }

    /**
     * Sets up a TCP listener on the configured address.
     *
     * Spawns a task that accepts incoming TCP connections and handles each in a separate task.
     * Each connection is processed using the configured message processor.
     *
     * @return A JoinHandle for the spawned listener task, or an error if setup fails
     */
    pub fn setup_tcp_listener(&self) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
        debug!(self.context.logger, "Enabling TCP server");
        let context = Arc::clone(&self.context);
        let processor = self.processor.clone();

        let tcp_handle = tokio::spawn(async move {
            let listener = TcpListener::bind(&context.config.tcp_bind_address).await.unwrap();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let processor = processor.clone();
                        tokio::spawn(async move {
                            Self::handle_tcp_socket(processor, stream)
                                .await
                                .expect("Failed to handle TCP socket");
                        });
                    }
                    Err(e) => error!(context.logger, "TCP accept error: {}", e),
                }
            }
        });
        Ok(tcp_handle)
    }

    /**
     * Sets up a UDP listener on the configured address.
     *
     * Spawns a task that receives UDP packets and processes them using the configured
     * message processor. Responses are sent back to the originating address.
     *
     * @return A JoinHandle for the spawned listener task, or an error if setup fails
     */
    pub fn setup_udp_listener(&self) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
        debug!(self.context.logger, "Enabling UDP server");
        let context = Arc::clone(&self.context);
        let processor = self.processor.clone();

        let udp_handle = tokio::spawn(async move {
            let udp_socket = UdpSocket::bind(&context.config.udp_bind_address).await
                .expect("Couldn't bind to address");
            Self::handle_udp_socket(processor, udp_socket)
                .await
                .expect("Failed to handle UDP socket");
        });
        Ok(udp_handle)
    }

    /**
     * Handles a message on a tcp connection
     *
     * Reads STUN messages from the connection, processes them, and writes responses back.
     *
     * @param processor The message processor to handle the STUN messages
     * @param stream The TCP connection stream
     * @return Result indicating success or failure
     */
    async fn handle_tcp_socket(
        processor: T,
        mut stream: TcpStream,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_MESSAGE_SIZE: usize = 4096; // per RFC5389 this is 64k, but we limit it
        const READ_TIMEOUT: Duration = Duration::from_secs(3);
        
        let mut header = [0u8; stun::HEADER_LENGTH as usize];
        let mut buffer = [0u8; MAX_MESSAGE_SIZE];
        let mut output = [0u8; MAX_MESSAGE_SIZE];
        let client_address = stream.peer_addr().ok();
    
        // Read header first
        timeout(READ_TIMEOUT, async {
            stream.read_exact(&mut header).await
        }).await??;
        
        // Extract message length from header (bytes 2-3)
        let message_length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if message_length > MAX_MESSAGE_SIZE - stun::HEADER_LENGTH as usize {
            return Err("Message too large".into());
        }
    
        // Copy header to buffer
        buffer[..stun::HEADER_LENGTH as usize].copy_from_slice(&header);
        
        // Read remaining message if any
        if message_length > 0 {
            timeout(
                READ_TIMEOUT,
                async {
                    stream.read_exact(&mut buffer[stun::HEADER_LENGTH as usize..stun::HEADER_LENGTH as usize + message_length]).await
                }
            ).await??;
        }
    
        let total_length = stun::HEADER_LENGTH as usize + message_length;
        let count = processor
            .process_message(&buffer[..total_length], client_address, &mut output)
            .await?;
        
        stream.write_all(&output[..count]).await?;
    
        Ok(())
    }

    /**
     * Handles UDP messages
     *
     * Receives UDP packets, processes them as STUN messages, and sends responses
     * back to the originating address. Runs until an error occurs.
     *
     * @param processor The message processor to handle the STUN messages  
     * @param socket The UDP socket to receive/send on
     * @return Result indicating success or failure
     */
    async fn handle_udp_socket(
        processor: T,
        socket: UdpSocket,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = [0u8; 1024];
        let mut output = [0u8; 1024];

        loop {
            let (n, client_addr) = socket.recv_from(&mut buffer).await?;

            let count = processor
                .process_message(&buffer[..n], Some(client_addr), &mut output)
                .await?;
            socket.send_to(&output[..count], client_addr).await?;
        }
    }
}
