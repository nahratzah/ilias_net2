/*
 * Copyright (c) 2012 Ariane van der Steldt <ariane@stack.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <ilias/net2/poetry.h>


/*
 * The poetry section in the library is because the protocol needs padding
 * during negotiation.  Since any kind of data will do, we'll put in some
 * quotes etc.  It's so much more interesting than binary data or binary 0.
 *
 * Hopefully, it'll brighten the day of the poor engineer debugging the
 * protocol, by reading it.
 */

namespace ilias {


ILIAS_NET2_LOCAL
const std::string poetry_txts[] = {
	"Secrecy and security aren't the same, "
	"even though it may seem that way. "
	"Only bad security relies on secrecy; "
	"good security works even if all the details of it "
	"are public. -- Bruce Schneier",

	"With the first link, the chain is forged.  "
	"The first speech censored, "
	"the first thought forbidden, "
	"the first freedom denied - "
	"chains us all, irrevocably. -- from Startrek TNG: The Drumhead",

	"They that can give up essential liberty "
	"to obtain a little temporary safety "
	"deserve neither liberty not safety. -- Benjamin Franklin",

	"Never attribute to malice "
	"that which is adequately explained by stupidity. -- Robert J. Hanlon",

	"Be conservative in what you do, "
	"be liberal in what you accept from others. -- Jon Postel",
};

ILIAS_NET2_LOCAL
const std::size_t poetry_sz = sizeof(poetry_txts) / sizeof(poetry_txts[0]);


} /* namespace ilias */
