package auth

import (
	"fmt"
)

// Wordlists for username generation
var (
	colors   = []string{"Red", "Blue", "Green", "Yellow", "Purple", "Orange", "Pink", "Black", "White", "Silver", "Gold", "Brown", "Turquoise", "Magenta", "Cyan", "Indigo", "Violet", "Crimson", "Azure", "Emerald"}
	animals  = []string{"Wolf", "Fox", "Lion", "Tiger", "Eagle", "Bear", "Dolphin", "Shark", "Hawk", "Owl", "Panther", "Dragon", "Phoenix", "Unicorn", "Griffin", "Raven", "Cobra", "Falcon", "Jaguar", "Lynx"}
	elements = []string{"Fire", "Water", "Earth", "Air", "Steel", "Light", "Shadow", "Thunder", "Ice", "Crystal", "Plasma", "Stone", "Wind", "Flame", "Ocean", "Mountain", "Storm", "Forest", "Desert", "Void"}
)

// GenerateUsername generates a random username in the format color-animal-element
func GenerateUsername() string {
	// Select random words from each category
	color := colors[SecureRandomInt(len(colors))]
	animal := animals[SecureRandomInt(len(animals))]
	element := elements[SecureRandomInt(len(elements))]

	return fmt.Sprintf("%s-%s-%s", color, animal, element)
}
