# Wake-on-LAN Server

Quick and dirty implementation of a Wake-on-Lan server that will be hosted in a home network. It was built to bypass the need for a paid service like Google Cloud Functions when waking from outside the local network by using Firebase's free tier. 

Commands (power on, or check status of a local computer) are made by the user via the [web frontend](https://github.com/wjin-lee/mirus-remote), and this server aims to process those commands. It traverses the network-address-translation (NAT) layer by using Firebase's real-time database. A simple setup where the server subscribes to changes is used.

See [here](https://en.wikipedia.org/wiki/Wake-on-LAN) for more on the Wake-on-LAN standard.

## Running
> [!NOTE]
> This script depends on Python version `>= 3.11`.

```sh
python3 ./wol_server.py <service_acc_cert_path>
```
Where `service_acc_cert_path` must be substituted for a path to the Google service account secrets file.

## Testing
*"Someday I'll get around to this"* 😭

