# SAGrey
Greylisting in Spamassassin using memcached.

## Abstract
Greylisting works by tempfailing a mail on the first delivery attempt and
accepting it on a later attempt, trying to destinguish between real mailservers
(which will retry the delivery) and spambots.
Traditionally, software like [postgrey](https://postgrey.schweikert.ch/) is used
for this, however, they often do not take things like sender reputation into
account and are diffucult to use across multiple mailservers.
SAGrey works around this by
* storing greylisting data in memcached which is easy to replicate and
* greylisting inside SpamAssassin only if the mail is above a certain threshold
  and
* caching greylisting results for servers, since another sender from the same
  host is likely to retry

## Usage
Load the module into your spamassassin installation:
```
loadplugin Mail::SpamAssassin::Plugin::SAGrey
```
and configure it like this:
```
header		SAGREY	eval:sagrey()
describe	SAGREY	Adds 0.1 to spam from first-time senders and marks messages
priority	SAGREY	1010 # run after AWL
score		SAGREY	0.1

sagrey_memcd_server 127.0.0.1:11211

add_header	all Plz-Greylist _SAGREY_
add_header	all Greylist-Reason _SAGREYREASON_
```
Afterwards, if a mail should be greylisted, it will have the header
`X-Plz-Greylist` set to 1. In e.g. Postfix, you'd then use this header filter:
```
/^X-Spam-Plz-Greylist: 1/	REJECT 4.2.0 Greylisted, please try again later.
```
to actually tempfail the mail.
