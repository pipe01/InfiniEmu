package services

type Location struct {
	Longitude, Latitude, Altitude, Precision float32
}

type LocationService struct {
	CurrentLocation Location
}

func (l LocationService) GetCurrent(priority string) Location {
	return l.CurrentLocation
}

func (l LocationService) GetLast() Location {
	return l.CurrentLocation
}
