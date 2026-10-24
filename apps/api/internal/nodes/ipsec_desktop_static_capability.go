package nodes

func ipsecDesktopStaticCapability(transit, recovery, reported int) int {
	if transit == 1 && recovery == 1 && reported == 1 {
		return 1
	}
	return 0
}
