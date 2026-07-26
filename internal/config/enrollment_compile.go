package config

import "fmt"

// CompiledEnrollment is the type-neutral runtime form of an enrollment block.
// Body is owned by the enrollment plugin; Liveness is shared framework policy.
type CompiledEnrollment struct {
	Name     string
	Type     string
	Body     any
	Liveness EnrollmentLiveness
}

func compileEnrollments(cp *CompiledPolicy, p *Policy) error {
	if cp == nil || p == nil || len(p.Enrollments) == 0 {
		return nil
	}
	seen := map[string]bool{}
	emit := func(name string) error {
		if seen[name] {
			return nil
		}
		ent, ok := p.Enrollments[name]
		if !ok || ent == nil {
			return nil
		}
		seen[name] = true
		if ent.Plugin == nil || ent.Plugin.CompileEnrollment == nil {
			return fmt.Errorf("enrollment %q type %q has no compiler", name, pluginType(ent.Plugin))
		}
		body, liveness, err := ent.Plugin.CompileEnrollment(ent.Body, name, cp.Profiles)
		if err != nil {
			return err
		}
		compiled := &CompiledEnrollment{
			Name:     name,
			Type:     ent.Plugin.Type,
			Body:     body,
			Liveness: liveness,
		}
		cp.Enrollments = append(cp.Enrollments, compiled)
		cp.EnrollmentsByName[name] = compiled
		return nil
	}

	// Follow declaration order for deterministic list output, then sweep any
	// enrollment omitted from Order defensively.
	for _, name := range p.Order {
		if _, ok := p.Enrollments[name]; ok {
			if err := emit(name); err != nil {
				return err
			}
		}
	}
	for name := range p.Enrollments {
		if err := emit(name); err != nil {
			return err
		}
	}
	return nil
}
