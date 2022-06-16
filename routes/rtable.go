package routes

type NetRoute struct {
	Metric      uint32 `json:"metric"`
	Destination string `json:"dest"`
	Gateway     string `json:"gateway"`
	Flags       uint32 `json:"flags"`
	NetIf       string `json:"iface"`
}
