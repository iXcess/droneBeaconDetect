# Python code for Drone Beacon Detection

Most of the commercial drones uses the Open WiFi connection for easy user configuration. This basically means that the drone will act as an Access Point (AP) to which a controller normally a phone to connect. Open WiFi also means that most commercial and hobbyist drones uses the IEEE 802.11 protocol. 

## Characteristics of an AP

An AP will usually broadcast beacon frames. [Beacon frames] are transmitted periodically, they serve to announce the presence of a wireless LAN and to synchronise the members of the service set. It contains all the information about the network.
![Beacon frame from wireshark](https://3.bp.blogspot.com/-FKoOO4JgZPg/Tx2twnX4B9I/AAAAAAAAADU/pOI4zC1fTw4/s1600/wireshark-beacon-frame.png)

### Prerequisites

What things you need to install the software and how to install them

```
Give examples
```

### Installing

A step by step series of examples that tell you how to get a development env running

Say what the step will be

```
Give the example
```

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Running the tests

Explain how to run the automated tests for this system

### Break down into end to end tests

Explain what these tests test and why

```
Give an example
```

### And coding style tests

Explain what these tests test and why

```
Give an example
```

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

* [Dropwizard](http://www.dropwizard.io/1.0.2/docs/) - The web framework used
* [Maven](https://maven.apache.org/) - Dependency Management
* [ROME](https://rometools.github.io/rome/) - Used to generate RSS Feeds

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Billie Thompson** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* etc

[Beacon frames]: https://en.wikipedia.org/wiki/Beacon_frame

