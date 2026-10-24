package nodes

func ipsecDesktopStaticCapability(transit, recovery, reported int) int {
	if transit == 1 && recovery == 1 && reported == 2 {
		return 2
	}
	return 0
}
