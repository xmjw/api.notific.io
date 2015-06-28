# api.notific.io

This is the server side API code for notific.io, providing the API layer mobile devices
connect to. It provides the ability to register a device, which generates an endpoint,
then receives incoming POST requests to send a notification.

## IDs and Tokens

Your ID and Token are both 8 digit alpha chars. This may not seem like it is super secure, but
this means there are something like (36^8)2 combinations, which is about 5.6*10^12 combinations.
If someone can really be bothered to hack you pair, then well done them. You can instantly use
the `recycle` endpoint and it resets your codes. So they have to start again. It is a simple
anti-spam mechanism. Because you can (should) be able to make changes and ship code very quickly.
Just be sure to handle those 401s in your code in case this happens. You do not want your
production system falling over because a reporting utility is failing!

## Triggering an event

Notific.io is designed to allow developers to easily drop an HTTP Post request into their code
and send a notification to their device. To make this as easy as possible, we include the token
in the JSON message. Messages must be sent by https, so this is adequate for now. Messages
should be in the following format:

    {
      "token": "1a1a1a1a",
      "message": "The notification I want to display",
      "action": "http://example.com/path/to/some/awesome"
      "sent": "2015-06-07T18:34:22+01:00" 
    }

Note we use iso8601 dates. Message sizes over 1kb are rejected automatically. But if you message
fits within that, you can have whatever you want, but will be truncated by your device. The
`action` is optional. If you do not provide one, opening the notificaiton will just open the app.
If you do provide one, the mobile app will open the  So a little over 900 bytes for core payload.

For example, you could triger this event using some ruby like so:

    HTTParty.post("https://api.notific.io/b2b2b2b2", { body: { token: "a1a2a3a4", message: "Wow!", sent: Time.now } }

Other examples will be added as I can be bothered.

## Open Source vs Paid

So, this is a paid for app, that is also open source. Why? Well, I figure the few dozen people who will download
and pay for the app should help cover the costs of my server. Above and beyond that is my own little reward for
bothering to create this damn thing. If you don't want to use my app, but do want to pay me, I'll a donate button
to the website at some point in the future. About the same time I add a website.

