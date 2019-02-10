# frozen_string_literal: true

require 'socket'

class SocketRecvTimeout < RuntimeError
  def message
    'Timeout while receiving message from socket'
  end
end

class LineOrientedSocket < TCPSocket
  def gets
    line = ''

    line += timed_getbyte until line.end_with?("\r\n")

    line
  end

  def gets_until_match(pattern)
    loop do
      line = gets
      break if line.match(pattern)
    end
  end

  def puts(data)
    send("#{data}\r\n", 0)
  end

  private

  TIMEOUT = 10

  def timed_getbyte
    recv_nonblock(1)
  rescue IO::EAGAINWaitReadable
    if IO.select([self], nil, nil, 10)
      recv_nonblock(1)
    else
      raise SocketRecvTimeout
    end
  end
end
