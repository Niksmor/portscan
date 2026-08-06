package portscan

import "sort"

type Ports struct {
	values []uint16
}

func List(ports ...uint16) (Ports, error) {
	for _, p := range ports {
		if p == 0 {
			return Ports{}, ErrInvalidPort
		}
	}
	return Ports{values: append([]uint16(nil), ports...)}, nil
}

func Range(from, to uint16) (Ports, error) {
	if from == 0 || to == 0 {
		return Ports{}, ErrInvalidPort
	}
	if from > to {
		from, to = to, from
	}
	ports := make([]uint16, 0, int(to-from)+1)
	for p := from; p <= to; p++ {
		ports = append(ports, p)
	}
	return Ports{values: ports}, nil
}

func Union(groups ...Ports) Ports {
	set := make(map[uint16]struct{})
	for _, group := range groups {
		for _, p := range group.values {
			if p == 0 {
				continue
			}
			set[p] = struct{}{}
		}
	}
	result := make([]uint16, 0, len(set))
	for p := range set {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return Ports{values: result}
}

func (p Ports) Values() ([]uint16, error) {
	if len(p.values) == 0 {
		return nil, ErrEmptyPorts
	}
	set := make(map[uint16]struct{})
	result := make([]uint16, 0, len(p.values))
	for _, port := range p.values {
		if port == 0 {
			return nil, ErrInvalidPort
		}
		if _, ok := set[port]; ok {
			continue
		}
		set[port] = struct{}{}
		result = append(result, port)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}
