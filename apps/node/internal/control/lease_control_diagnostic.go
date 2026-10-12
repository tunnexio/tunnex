package control

// Deliberately retains the public sentinel and never exposes remote or transport text.
type leaseControlFailure struct{ category string }

func (e leaseControlFailure) Error() string                  { return ErrIPsecControl.Error() }
func (e leaseControlFailure) Unwrap() error                  { return ErrIPsecControl }
func (e leaseControlFailure) IPsecLeaseFailureStage() string { return e.category }
