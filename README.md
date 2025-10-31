oddjob
======
 
The **oddjobd** service receives requests to do things over the
[D-Bus](http://www.freedesktop.org/wiki/Software/dbus) system bus.  Depending
on whether or not the requesting user is authorized to have **oddjobd** do what
it asked, the daemon will spawn a helper process to actually do the work.  When
the helper exits, **oddjobd** collects its output and exit status and sends
them back to the original requester. 
 
It's kind of like [CGI](http://en.wikipedia.org/wiki/Common_Gateway_Interface),
except it's for D-Bus instead of a web server. 
 
Documentation
=============
The [original docs](https://pagure.io/oddjob/raw/master/f/doc/oddjob.html) are
brief but comprehensive.  And there's always a [to-do
list](https://pagure.io/oddjob/blob/master/f/TODO).
 
Get It!
=======
The current release is stable.  Go ahead and
[download](https://releases.pagure.org/oddjob/) it and give it a go.  The
_oddjob_ package is also available in prepackaged form in Fedora and recent
releases of your friendly neighborhood Enterprise Linux.
