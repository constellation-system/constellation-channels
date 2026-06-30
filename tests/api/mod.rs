// Copyright © 2024-26 The Johns Hopkins Applied Physics Laboratory LLC.
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

use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_streams::threads::Tokens;
use constellation_streams::threads::TokensCtx;
use mio::Token;

mod far;
mod near;

pub(crate) struct ExampleCtx<Ctx>
where Ctx: NSNameCachesCtx {
    inner: Ctx,
    tokens: Tokens
}

impl<Ctx> ExampleCtx<Ctx>
where Ctx: NSNameCachesCtx {
    #[inline]
    fn new(ctx: Ctx) -> Self {
        ExampleCtx {
            inner: ctx,
            tokens: Tokens::new()
        }
    }
}

impl<Ctx> NSNameCachesCtx for ExampleCtx<Ctx>
where Ctx: NSNameCachesCtx {
    type NameCaches = Ctx::NameCaches;

    #[inline]
    fn name_caches(&mut self) -> &mut Self::NameCaches {
        self.inner.name_caches()
    }
}

impl<Ctx> TokensCtx for ExampleCtx<Ctx>
where Ctx: NSNameCachesCtx {
    #[inline]
    fn token(&mut self) -> Token {
        self.tokens.token()
    }

    #[inline]
    fn free_token(
        &mut self,
        token: Token
    ) {
        self.tokens.free_token(token)
    }
}
