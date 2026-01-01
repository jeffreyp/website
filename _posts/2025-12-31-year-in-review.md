---
layout: post
title: "2025 Year In Review"
excerpt_separator: <!-- more -->
---
In 2025, I purchased a Claude Pro subscription. Guess when?

<div class="photo-full-width" markdown="1">
![image github](/assets/images/github-2025.png)
</div>

With tons of help from my new friend Claude Code, I started (because you never really complete) some fun projects in 2025:

* I created a [Video Poker](https://github.com/jeffreyp/videopoker) game that updates winning hand probabilities in real time as you select cards. I threw this together in a hotel room in Vegas in under an hour out of nothing but curiosity.
* At work, we spent a lot of time dealing with construction cranes appearing unexpectedly in our airspace. I thought, there has to be a data source somewhere I can use to automate this. It turns out there are three:  1) the FAA data object files, 2) the FAA OE/AAA database, and 3) NOTAMs. I built a [website](https://github.com/jeffreyp/faa-crane-viewer) that lets you search for **registered** obstacles within some nautical miles of a U.S. address. Turns out most of the data sources are unreliable (especially during federal government shutdowns) but building the site and automating daily data collection and site builds was a fun exercise.
* I really miss Google Reader, and after trying both Feedly and Reeder, I was left wanting. After Google killed Reeder, someone resurrected it for awhile as an open source project, but it hadn't been maintained. I pointed Claude at that person's code and added bells and whistles, and I now use it exclusively for my daily RSS reading needs. See [GoRead2](https://github.com/jeffreyp/goread2). I'm currently the only customer/user, but it is fully integrated with Stripe and supports a monthly subscription so *in theory* others could use it, too. I'm not exactly keeping it secret but it has not had a proper alpha/beta test so there are likely bugs to be found.

Those were the big ones. As for other major time savers with Claude and friends, I don't write scripts anymore or spend much time caring about what data I need to extract from a database. I just `select * from table_name`, download everything as a CSV file, and let Claude Code figure it out.

Not sure what to expect in 2026, but happy new year to anyone out there reading this.
