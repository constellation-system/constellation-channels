// Copyright © 2024 The Johns Hopkins Applied Physics Laboratory LLC.
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License,
// version 3, as published by the Free Software Foundation.  If you
// would like to purchase a commercial license for this software, please
// contact APL’s Tech Transfer at 240-592-0817 or
// techtransfer@jhuapl.edu.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

use crate::near::NearReceiver;
use crate::near::NearSender;
use std::io::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::Receiver;

/// Errors that can occur performing a [send](NearSender::send)
/// operation.
#[derive(Debug)]
pub enum SendError<T> {
    Send(std::sync::mpsc::SendError<T>),
    IO(Error)
}

#[derive(Clone)]
pub struct ChannelSender<T> {
    sender: Sender<T>,
}

pub struct ChannelReceiver<T> {
    receiver: Receiver<T>,
}

impl<T> Display for SendError<T> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            SendError::Send(err) => err.fmt(f),
            SendError::IO(err) => err.fmt(f)
        }
    }
}

impl<T> NearReceiver<T> for ChannelReceiver<T> {
    type RecvError = TryRecvError;

    #[inline]
    fn recv(&self) -> Result<T, Self::RecvError> {
        self.receiver.try_recv()
    }
}

impl<T> NearSender<T> for ChannelSender<T> {
    type SendError = SendError<T>;

    #[inline]
    fn send(&self, val: T) -> Result<(), Self::SendError> {
        self.sender.send(val).map_err(|err| SendError::Send(err))?;
        self.waker.wake().map_err(|err| SendError::IO(err))
    }
}

impl<T> ChannelReceiver<T> {
    #[inline]
    pub fn new<'a>(poll: Poll, token: Token) -> Result<(ChannelSender<T>,
                                                        ChannelReceiver<T>),
                                                       Error> {
        let (sender, receiver) = channel();
        let waker = Waker::new(poll.registry(), token)?;
        let receiver = ChannelReceiver { receiver: receiver, token: token,
                                         poll: poll };
        let sender = ChannelSender { sender: sender, waker: Arc::new(waker) };

        Ok((sender, receiver))
    }

    #[inline]
    pub fn token(&self) -> &Token {
        &self.token
    }
}
